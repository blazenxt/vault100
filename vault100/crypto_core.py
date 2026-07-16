"""Vault100 cryptographic core — format v2 (with v1 backward compatibility).

v2 design
---------
* **Envelope encryption** — every vault has a random per-file File
  Encryption Key (FEK). The FEK is wrapped (XChaCha20-Poly1305) by a Key
  Encryption Key (KEK) derived from your password (+ optional keyfile).
  ⇒ Change the password in milliseconds without re-encrypting the data.

* **Cipher** — XChaCha20-Poly1305 via libsodium *secretstream*
  (AEAD, 192-bit nonces, auto re-key, truncation-proof TAG_FINAL).

* **Cascade mode** (`--cascade`) — each chunk is *additionally* sealed
  with **AES-256-GCM** under an independent key before entering the
  secretstream. If either cipher is ever broken, the other still protects
  the data. Requires the `cryptography` package.

* **Keyfile** (`--keyfile`) — the KEK becomes
  ``HKDF-SHA256( Argon2id(password) ‖ BLAKE2b(keyfile) )``.
  Both factors are needed; either missing ⇒ decryption fails.

* **KDF** — Argon2id, random 32-byte salt, params stored in header.
  `calibrate_profile()` measures the host and tunes hardness ("max").

v2 file layout (little-endian)
------------------------------
=====  =====  ================================================
 off    size  field
=====  =====  ================================================
  0      8   magic ``b"V100ENC2"``
  8      1   format version (2)
  9      1   kdf id (1 = Argon2id)
 10      4   kdf memory, KiB
 14      4   kdf time cost
 18      1   kdf parallelism
 19      1   flags (bit0 = cascade, bit1 = keyfile required)
 20     32   salt (KEK derivation)
 52     24   wrap nonce (XChaCha20-Poly1305)
 76   48/80  wrapped FEK (32 B + 16 B tag; 64 B + tag if cascade)
        24   secretstream header
        ..   chunks: ``[uint32 ct_len][ciphertext] ...``
=====  =====  ================================================

v1 files (magic ``V100ENC1``) remain decryptable forever.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import struct
import zlib
import tempfile
import time
from contextlib import contextmanager

import nacl.bindings as _nb
import nacl.exceptions as _ne
from argon2.low_level import Type as _Argon2Type
from argon2.low_level import hash_secret_raw

try:  # newer PyNaCl: explicit state object API
    from nacl.bindings.crypto_secretstream import (
        crypto_secretstream_xchacha20poly1305_state as _SSState)
except ImportError:  # older PyNaCl API
    _SSState = None

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM
except ImportError:
    _AESGCM = None

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

MAGIC_V1 = b"V100ENC1"
MAGIC_V2 = b"V100ENC2"
FORMAT_V1 = 1
FORMAT_V2 = 2
KDF_ARGON2ID = 1
CIPHER_SECRETSTREAM = 1

FLAG_CASCADE = 0x01
FLAG_KEYFILE = 0x02
_KNOWN_FLAGS = FLAG_CASCADE | FLAG_KEYFILE

SALT_BYTES = 32
KEY_BYTES = 32
ARGON2_VERSION = 19
CHUNK_SIZE = 1024 * 1024          # plaintext bytes per stream message
META_MAX = 4096
WRAP_NONCE_BYTES = 24
STREAM_HDR_BYTES = 24

TAG_MESSAGE = _nb.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE
TAG_FINAL = _nb.crypto_secretstream_xchacha20poly1305_TAG_FINAL
ABYTES = _nb.crypto_secretstream_xchacha20poly1305_ABYTES  # 17
GCM_TAG = 16

_HEADER_V1 = struct.Struct("<8sBBIIBB32s24s")   # 76 bytes total
_FIXED_V2 = struct.Struct("<8sBBIIBB32s")       # 52 bytes (through salt)
LEN_PREFIX = struct.Struct("<I")

# Anti-DoS sanity caps for parameters read from (untrusted) file headers.
_MAX_MEM_KIB = 4 * 1024 * 1024    # 4 GiB
_MAX_TIME = 64
_MAX_PARALLELISM = 16

KDF_PROFILES = {
    "standard": dict(memory_kib=128 * 1024, time_cost=3, parallelism=4),
    "paranoid": dict(memory_kib=512 * 1024, time_cost=4, parallelism=4),
}
DEFAULT_PROFILE = "standard"

_FAST_PROFILE = dict(memory_kib=8 * 1024, time_cost=1, parallelism=4)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class VaultError(Exception):
    """Base class for all Vault100 errors."""


class VaultFormatError(VaultError):
    """Not a valid Vault100 container, or structurally corrupted."""


class VaultAuthError(VaultError):
    """Wrong password/keyfile, or tampered data. Indistinguishable
    by design — the format reveals nothing about *which* failed."""


class VaultCancelled(VaultError):
    """The operation was cancelled (e.g. from the GUI)."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def _init_push(key: bytes):
    if _SSState is not None:
        state = _SSState()
        header = _nb.crypto_secretstream_xchacha20poly1305_init_push(
            state, key)
        return state, header
    return _nb.crypto_secretstream_xchacha20poly1305_init_push(key)


def _init_pull(stream_header: bytes, key: bytes):
    if _SSState is not None:
        state = _SSState()
        _nb.crypto_secretstream_xchacha20poly1305_init_pull(
            state, stream_header, key)
        return state
    return _nb.crypto_secretstream_xchacha20poly1305_init_pull(
        stream_header, key)


def _profile_params(profile: str) -> dict:
    if os.environ.get("VAULT100_FAST_KDF") == "1":
        return dict(_FAST_PROFILE)
    try:
        return dict(KDF_PROFILES[profile])
    except KeyError:
        raise VaultError(f"unknown KDF profile: {profile!r}") from None


def _validate_kdf(memory_kib: int, time_cost: int, parallelism: int) -> None:
    if not (8 <= memory_kib <= _MAX_MEM_KIB):
        raise VaultFormatError("header KDF memory out of allowed range")
    if not (1 <= time_cost <= _MAX_TIME):
        raise VaultFormatError("header KDF time cost out of allowed range")
    if not (1 <= parallelism <= _MAX_PARALLELISM):
        raise VaultFormatError("header KDF parallelism out of allowed range")


def _derive_key(password: bytes, salt: bytes, *, memory_kib: int,
                time_cost: int, parallelism: int) -> bytes:
    return hash_secret_raw(
        secret=password, salt=salt, time_cost=time_cost,
        memory_cost=memory_kib, parallelism=parallelism,
        hash_len=KEY_BYTES, type=_Argon2Type.ID, version=ARGON2_VERSION)


def _hkdf_sha256(ikm: bytes, *, salt: bytes, info: bytes,
                 length: int = 32) -> bytes:
    """RFC 5869 HKDF-SHA256 (single-extract / multi-block expand)."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]),
                         hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


def _derive_kek(password: bytes, salt: bytes, params: dict,
                key_data: bytes | None) -> bytes:
    raw = _derive_key(password, salt, **params)
    if key_data is None:
        return raw
    return _hkdf_sha256(raw + key_data, salt=salt,
                        info=b"V100-KEK-v2", length=KEY_BYTES)


def _ctr_nonce(index: int) -> bytes:
    """96-bit deterministic GCM nonce; safe because the key is unique per
    vault (random FEK) and each index is used at most once."""
    return struct.pack("<Q", index) + b"\x00\x00\x00\x00"


def _new_aes(key: bytes):
    if _AESGCM is None:
        raise VaultError(
            "cascade mode needs the 'cryptography' package: "
            "pip install cryptography")
    return _AESGCM(key)


def _read_exact(fin, n: int) -> bytes:
    buf = fin.read(n)
    if len(buf) != n:
        raise VaultFormatError("file truncated mid-chunk")
    return buf


@contextmanager
def _atomic_writer(path: str):
    """Write to a temp file in the same directory; publish on success only."""
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".v100-tmp-")
    try:
        with os.fdopen(fd, "wb") as f:
            yield f
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def sanitize_filename(name: str) -> str:
    name = name.replace("\\", "/").split("/")[-1]
    name = name.replace(":", "_").strip().lstrip(".")
    if not name or name in (".", ".."):
        return "decrypted.bin"
    return name[:255]


def unique_path(path: str) -> str:
    if not os.path.exists(path):
        return path
    root, ext = os.path.splitext(path)
    i = 1
    while os.path.exists(candidate := f"{root} ({i}){ext}"):
        i += 1
    return candidate


# ---------------------------------------------------------------------------
# Encryption (v2)
# ---------------------------------------------------------------------------

class _GzipReader:
    """File-like adapter: pulls plaintext, yields its gzip stream.

    Used by ``compress=True`` so the cipher only ever sees the (usually
    smaller) gzip bytes; the metadata flag ``"gz": true`` makes readers
    reverse the wrap transparently.
    """

    def __init__(self, fin) -> None:
        self._fin = fin
        self._co = zlib.compressobj(6, zlib.DEFLATED, 16 + zlib.MAX_WBITS)
        self._buf = bytearray()
        self._eof = False

    def _fill(self, want: int) -> None:
        while len(self._buf) < want and not self._eof:
            chunk = self._fin.read(max(want - len(self._buf), 65536))
            if chunk:
                self._buf += self._co.compress(chunk)
            else:
                self._buf += self._co.flush()
                self._eof = True

    def read(self, n: int = -1) -> bytes:
        if n is None or n < 0:
            while not self._eof:
                self._fill(1 << 20)
            out = bytes(self._buf)
            self._buf.clear()
            return out
        self._fill(n)
        out = bytes(self._buf[:n])
        del self._buf[:n]
        return out


def encrypt_stream(fin, fout, password: bytes, *,
                   profile: str = DEFAULT_PROFILE,
                   params: dict | None = None,
                   key_data: bytes | None = None,
                   cascade: bool = False,
                   compress: bool = False,
                   total: int | None = None,
                   progress=None,
                   metadata: dict | None = None) -> None:
    """Encrypt *fin* → *fout* as a Vault100 v2 container.

    *params*    explicit KDF dict (overrides *profile*).
    *key_data*  digest of a keyfile (from keyfile.load_keyfile) — becomes
                a mandatory second factor, recorded in the header flags.
    *compress*  gzip the payload first; recorded as ``"gz": true`` in the
                metadata and reversed transparently on decryption.
    *progress*  callable ``progress(done, total)``; may raise
                :class:`VaultCancelled`.
    """
    p = dict(params) if params else _profile_params(profile)
    _validate_kdf(**p)

    if compress:
        # stream-compress: the encrypted stream carries gzip bytes, the
        # metadata records the flag (reversed transparently on decrypt)
        fin = _GzipReader(fin)
        metadata = dict(metadata or {})
        metadata["gz"] = True
        total = None            # compressed length is unknowable up front

    salt = os.urandom(SALT_BYTES)
    fek = os.urandom(64 if cascade else KEY_BYTES)
    kek = _derive_kek(password, salt, p, key_data)

    wnonce = os.urandom(WRAP_NONCE_BYTES)
    wrapped = _nb.crypto_aead_xchacha20poly1305_ietf_encrypt(
        fek, None, wnonce, kek)
    kek = None

    flags = ((FLAG_CASCADE if cascade else 0)
             | (FLAG_KEYFILE if key_data is not None else 0))
    fixed = _FIXED_V2.pack(MAGIC_V2, FORMAT_V2, KDF_ARGON2ID,
                           p["memory_kib"], p["time_cost"],
                           p["parallelism"], flags, salt)

    state, stream_hdr = _init_push(fek[:KEY_BYTES])
    aes = _new_aes(fek[KEY_BYTES:]) if cascade else None
    fek = None

    header = fixed + wnonce + bytes(wrapped) + stream_hdr
    fout.write(header)

    # AAD context: derived from the immutable stream header only, so
    # `change_password` (which deliberately rewrites salt/nonce/wrap)
    # never invalidates authenticated chunks. Integrity of the mutable
    # KEK zone is already enforced by the Poly1305 tag on the FEK wrap —
    # any edit yields a wrong KEK ⇒ unlock fails.
    stream_ctx = b"V100-CTX" + stream_hdr

    counter = {"i": 0}

    def seal(msg: bytes) -> bytes:
        if aes is not None:
            msg = aes.encrypt(_ctr_nonce(counter["i"]), msg, stream_ctx)
        counter["i"] += 1
        return msg

    # First stream message: encrypted metadata, stream context as AAD.
    meta = dict(metadata or {})
    meta.setdefault("v", 2)
    meta_blob = json.dumps(meta, separators=(",", ":")).encode("utf-8")
    if len(meta_blob) > META_MAX:
        raise VaultError("metadata too large")
    ct = _nb.crypto_secretstream_xchacha20poly1305_push(
        state, seal(meta_blob), stream_ctx, TAG_MESSAGE)
    fout.write(LEN_PREFIX.pack(len(ct)))
    fout.write(ct)

    done = 0
    pending = fin.read(CHUNK_SIZE)
    while True:
        nxt = fin.read(CHUNK_SIZE)
        tag = TAG_FINAL if not nxt else TAG_MESSAGE
        ct = _nb.crypto_secretstream_xchacha20poly1305_push(
            state, seal(pending), b"", tag)
        fout.write(LEN_PREFIX.pack(len(ct)))
        fout.write(ct)
        done += len(pending)
        if progress is not None:
            progress(done, total if total is not None else 0)
        if tag == TAG_FINAL:
            break
        pending = nxt


def encrypt_file(src: str, dst: str, password: bytes, **kw) -> str:
    """Encrypt file *src* → *dst* (atomically). Returns *dst*."""
    st = os.stat(src)
    metadata = {"name": os.path.basename(src), "size": st.st_size,
                "mtime": int(st.st_mtime)}
    kw.setdefault("total", st.st_size)
    with open(src, "rb") as fin, _atomic_writer(dst) as fout:
        encrypt_stream(fin, fout, password, metadata=metadata, **kw)
    return dst


# ---------------------------------------------------------------------------
# Decryption (dispatch v1 / v2)
# ---------------------------------------------------------------------------

def decrypt_stream(fin, fout, password: bytes, *,
                   key_data: bytes | None = None,
                   total: int | None = None, progress=None) -> dict:
    """Decrypt *fin* → *fout*; auto-detects format version.

    Returns the stored metadata. Raises :class:`VaultAuthError` on wrong
    password/keyfile or any modification of the vault.
    """
    magic = _read_exact(fin, 8)
    if magic == MAGIC_V1:
        if key_data is not None:
            raise VaultError("v1 vaults have no keyfile support; "
                             "this file predates keyfiles")
        return _decrypt_stream_v1(fin, fout, password, magic,
                                  total=total, progress=progress)
    if magic != MAGIC_V2:
        raise VaultFormatError("not a Vault100-encrypted file (bad magic)")
    return _decrypt_stream_v2(fin, fout, password, magic,
                              key_data=key_data, total=total,
                              progress=progress)


def _decrypt_stream_v2(fin, fout, password, magic, *, key_data, total,
                       progress) -> dict:
    rest = _read_exact(fin, _FIXED_V2.size - 8)
    (_m, ver, kdf_id, mem, t_cost, par, flags, salt) = \
        _FIXED_V2.unpack(magic + rest)
    if ver != FORMAT_V2:
        raise VaultFormatError(f"unsupported format version {ver}")
    if kdf_id != KDF_ARGON2ID:
        raise VaultFormatError(f"unknown KDF id {kdf_id}")
    if flags & ~_KNOWN_FLAGS:
        raise VaultFormatError(f"unknown header flags 0x{flags:02x}")
    _validate_kdf(mem, t_cost, par)

    cascade = bool(flags & FLAG_CASCADE)
    if (flags & FLAG_KEYFILE) and key_data is None:
        raise VaultError("this vault requires its keyfile (--keyfile)")
    fek_len = 64 if cascade else KEY_BYTES

    wnonce = _read_exact(fin, WRAP_NONCE_BYTES)
    wrapped = _read_exact(fin, fek_len + 16)  # Poly1305 auth tag
    stream_hdr = _read_exact(fin, STREAM_HDR_BYTES)
    header = magic + rest + wnonce + wrapped + stream_hdr

    kek = _derive_kek(password, salt,
                      dict(memory_kib=mem, time_cost=t_cost,
                           parallelism=par), key_data)
    try:
        fek = _nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
            wrapped, None, wnonce, kek)
    except (_ne.CryptoError, ValueError):
        raise VaultAuthError(
            "unlock failed: wrong password/keyfile or corrupted vault"
        ) from None
    kek = None

    state = _init_pull(stream_hdr, fek[:KEY_BYTES])
    aes = _new_aes(fek[KEY_BYTES:]) if cascade else None
    fek = None
    stream_ctx = b"V100-CTX" + stream_hdr

    idx = 0
    metadata: dict | None = None
    done = len(header)
    gunzip = None   # zlib.decompressobj once metadata says "gz": true

    while True:
        raw_len = fin.read(LEN_PREFIX.size)
        if not raw_len:
            raise VaultFormatError(
                "file truncated: missing end-of-stream marker")
        if len(raw_len) < LEN_PREFIX.size:
            raise VaultFormatError("file truncated mid-chunk")
        (ct_len,) = LEN_PREFIX.unpack(raw_len)
        max_ct = CHUNK_SIZE + GCM_TAG + ABYTES
        if ct_len < ABYTES or ct_len > max_ct:
            raise VaultFormatError("invalid chunk length")
        ct = _read_exact(fin, ct_len)
        done += LEN_PREFIX.size + ct_len
        try:
            payload, tag = _nb.crypto_secretstream_xchacha20poly1305_pull(
                state, ct, stream_ctx if metadata is None else b"")
            if aes is not None:
                payload = aes.decrypt(_ctr_nonce(idx), payload, stream_ctx)
        except (_ne.CryptoError, ValueError):
            raise VaultAuthError(
                "decryption failed: wrong password/keyfile or "
                "corrupted vault") from None
        idx += 1

        if metadata is None:
            if tag != TAG_MESSAGE or len(payload) > META_MAX:
                raise VaultFormatError("invalid metadata chunk")
            try:
                metadata = json.loads(payload.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise VaultFormatError("corrupt metadata chunk") from None
            if not isinstance(metadata, dict):
                raise VaultFormatError("corrupt metadata chunk")
            if progress is not None:
                progress(done, total if total is not None else 0)
            if isinstance(metadata, dict) and metadata.get("gz") is True:
                gunzip = zlib.decompressobj(16 + zlib.MAX_WBITS)
            continue

        if gunzip is not None:
            try:
                payload = gunzip.decompress(payload)
            except zlib.error:
                raise VaultFormatError("corrupt gzip payload") from None
        fout.write(payload)
        if progress is not None:
            progress(done, total if total is not None else 0)
        if tag == TAG_FINAL:
            break

    if gunzip is not None:
        try:
            payload = gunzip.flush()
        except zlib.error:
            raise VaultFormatError("corrupt gzip payload") from None
        if not gunzip.eof:
            raise VaultFormatError("truncated gzip payload")
        fout.write(payload)

    if fin.read(1):
        raise VaultFormatError("trailing data after end of encrypted stream")
    return metadata or {}


def _decrypt_stream_v1(fin, fout, password, magic, *, total, progress) -> dict:
    """Legacy reader for original v1 vaults."""
    rest = _read_exact(fin, _HEADER_V1.size - 8)
    (_m, version, kdf_id, mem, t_cost, par, cipher, salt, stream_hdr) = \
        _HEADER_V1.unpack(magic + rest)
    if version != FORMAT_V1:
        raise VaultFormatError(f"unsupported v1 version {version}")
    if kdf_id != KDF_ARGON2ID or cipher != CIPHER_SECRETSTREAM:
        raise VaultFormatError("unknown v1 algorithm ids")
    _validate_kdf(mem, t_cost, par)

    key = _derive_key(password, salt, memory_kib=mem, time_cost=t_cost,
                      parallelism=par)
    state = _init_pull(stream_hdr, key)
    key = None

    aad = magic + rest
    metadata: dict | None = None
    done = _HEADER_V1.size
    while True:
        raw_len = fin.read(LEN_PREFIX.size)
        if not raw_len:
            raise VaultFormatError(
                "file truncated: missing end-of-stream marker")
        if len(raw_len) < LEN_PREFIX.size:
            raise VaultFormatError("file truncated mid-chunk")
        (ct_len,) = LEN_PREFIX.unpack(raw_len)
        if ct_len < ABYTES or ct_len > CHUNK_SIZE + ABYTES:
            raise VaultFormatError("invalid chunk length")
        ct = _read_exact(fin, ct_len)
        done += LEN_PREFIX.size + ct_len
        try:
            msg, tag = _nb.crypto_secretstream_xchacha20poly1305_pull(
                state, ct, aad)
        except (_ne.CryptoError, ValueError):
            raise VaultAuthError(
                "decryption failed: wrong password or corrupted file"
            ) from None
        aad = b""
        if metadata is None:
            if tag != TAG_MESSAGE or len(msg) > META_MAX:
                raise VaultFormatError("invalid metadata chunk")
            try:
                metadata = json.loads(msg.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                raise VaultFormatError("corrupt metadata chunk") from None
            if not isinstance(metadata, dict):
                raise VaultFormatError("corrupt metadata chunk")
            if progress is not None:
                progress(done, total if total is not None else 0)
            continue
        fout.write(msg)
        if progress is not None:
            progress(done, total if total is not None else 0)
        if tag == TAG_FINAL:
            break
    if fin.read(1):
        raise VaultFormatError("trailing data after end of encrypted stream")
    return metadata or {}


def decrypt_file(src: str, dst: str, password: bytes, **kw) -> dict:
    """Decrypt file *src* → *dst* (atomically). Returns metadata."""
    kw.setdefault("total", os.stat(src).st_size)
    with open(src, "rb") as fin, _atomic_writer(dst) as fout:
        return decrypt_stream(fin, fout, password, **kw)


# ---------------------------------------------------------------------------
# Password change / inspection / calibration
# ---------------------------------------------------------------------------

def _read_v2_header(f) -> dict:
    """Parse a v2 header from an open file positioned at 0."""
    magic = _read_exact(f, 8)
    if magic == MAGIC_V1:
        raise VaultError("v1 vault: `passwd` needs v2 — re-encrypt to "
                         "upgrade this file")
    if magic != MAGIC_V2:
        raise VaultFormatError("not a Vault100-encrypted file")
    rest = _read_exact(f, _FIXED_V2.size - 8)
    (_m, ver, kdf_id, mem, t_cost, par, flags, salt) = \
        _FIXED_V2.unpack(magic + rest)
    if ver != FORMAT_V2 or kdf_id != KDF_ARGON2ID:
        raise VaultFormatError("unsupported v2 header")
    if flags & ~_KNOWN_FLAGS:
        raise VaultFormatError(f"unknown header flags 0x{flags:02x}")
    _validate_kdf(mem, t_cost, par)
    cascade = bool(flags & FLAG_CASCADE)
    fek_len = 64 if cascade else KEY_BYTES
    wnonce = _read_exact(f, WRAP_NONCE_BYTES)
    wrapped = _read_exact(f, fek_len + 16)
    return dict(params=dict(memory_kib=mem, time_cost=t_cost,
                            parallelism=par),
                flags=flags, salt=salt, wnonce=wnonce, wrapped=wrapped,
                fek_len=fek_len, cascade=cascade, fixed=magic + rest)


def change_password(path: str, old_password: bytes, new_password: bytes, *,
                    old_key_data: bytes | None = None,
                    new_key_data: bytes | None = None,
                    new_params: dict | str | None = None) -> None:
    """Re-wrap the vault's file key under a new password — no data rewrite.

    .. warning:: anyone holding a *copy of the old vault* plus the old
       password can still decrypt that copy (same as LUKS/VeraCrypt).
    """
    with open(path, "r+b") as f:
        h = _read_v2_header(f)
        if h["flags"] & FLAG_KEYFILE and old_key_data is None:
            raise VaultError("vault requires its keyfile (--keyfile)")
        kek = _derive_kek(old_password, h["salt"], h["params"], old_key_data)
        try:
            fek = _nb.crypto_aead_xchacha20poly1305_ietf_decrypt(
                h["wrapped"], None, h["wnonce"], kek)
        except (_ne.CryptoError, ValueError):
            raise VaultAuthError("wrong current password or keyfile") from None
        kek = None

        if isinstance(new_params, str):
            p = _profile_params(new_params)
        elif new_params is None:
            p = h["params"]
        else:
            p = dict(new_params)
        _validate_kdf(**p)

        salt2 = os.urandom(SALT_BYTES)
        kek2 = _derive_kek(new_password, salt2, p, new_key_data)
        wnonce2 = os.urandom(WRAP_NONCE_BYTES)
        wrapped2 = _nb.crypto_aead_xchacha20poly1305_ietf_encrypt(
            fek, None, wnonce2, kek2)
        flags2 = (h["flags"] & FLAG_CASCADE) | \
            (FLAG_KEYFILE if new_key_data is not None else 0)
        fixed2 = _FIXED_V2.pack(MAGIC_V2, FORMAT_V2, KDF_ARGON2ID,
                                p["memory_kib"], p["time_cost"],
                                p["parallelism"], flags2, salt2)
        f.seek(0)
        f.write(fixed2 + wnonce2 + bytes(wrapped2))
        f.flush()
        os.fsync(f.fileno())


def vault_info(path: str) -> dict:
    """Return non-secret header facts about a vault file."""
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        magic = f.read(8)
        if magic == MAGIC_V1:
            rest = _read_exact(f, _HEADER_V1.size - 8)
            (_m, _v, _k, mem, t_cost, par, _c, _s, _sh) = \
                _HEADER_V1.unpack(magic + rest)
            return dict(format=1, cipher="XChaCha20-Poly1305 (secretstream)",
                        cascade=False, keyfile=False,
                        kdf=dict(memory_kib=mem, time_cost=t_cost,
                                 parallelism=par), size=size)
        f.seek(0)
        h = _read_v2_header(f)
    return dict(format=2,
                cipher=("AES-256-GCM ⟶ XChaCha20-Poly1305" if h["cascade"]
                        else "XChaCha20-Poly1305 (secretstream)"),
                cascade=h["cascade"],
                keyfile=bool(h["flags"] & FLAG_KEYFILE),
                kdf=h["params"], size=size)


def calibrate_profile(target_seconds: float = 2.0, *,
                      max_kib: int = 1024 * 1024,
                      parallelism: int = 4) -> dict:
    """Measure this machine and return KDF params costing ~target seconds."""
    sample_kib = 64 * 1024
    salt = os.urandom(16)
    t0 = time.perf_counter()
    _derive_key(b"vault100-calibration", salt, memory_kib=sample_kib,
                time_cost=1, parallelism=parallelism)
    dt = max(time.perf_counter() - t0, 0.01)

    mem = int(min(max_kib, max(64 * 1024,
                               sample_kib * target_seconds / dt)))
    est = dt * (mem / sample_kib)
    time_cost = int(min(_MAX_TIME, max(1, target_seconds / est)))
    return dict(memory_kib=mem, time_cost=time_cost,
                parallelism=parallelism)


# ---------------------------------------------------------------------------
# v1 legacy encrypt (kept for compatibility tests & migrations)
# ---------------------------------------------------------------------------

def _encrypt_stream_v1(fin, fout, password: bytes, *,
                       profile: str = DEFAULT_PROFILE,
                       total: int | None = None, progress=None,
                       metadata: dict | None = None) -> None:
    """Original v1 format — retained so old tests/migrations can create
    v1 files. New code should use :func:`encrypt_stream` (v2)."""
    p = _profile_params(profile)
    salt = os.urandom(SALT_BYTES)
    key = _derive_key(password, salt, **p)
    state, stream_header = _init_push(key)
    key = None
    header = _HEADER_V1.pack(MAGIC_V1, FORMAT_V1, KDF_ARGON2ID,
                             p["memory_kib"], p["time_cost"],
                             p["parallelism"], CIPHER_SECRETSTREAM,
                             salt, stream_header)
    fout.write(header)
    meta = dict(metadata or {})
    meta.setdefault("v", 1)
    blob = json.dumps(meta, separators=(",", ":")).encode("utf-8")[:META_MAX]
    ct = _nb.crypto_secretstream_xchacha20poly1305_push(
        state, blob, header, TAG_MESSAGE)
    fout.write(LEN_PREFIX.pack(len(ct)))
    fout.write(ct)
    done = 0
    pending = fin.read(CHUNK_SIZE)
    while True:
        nxt = fin.read(CHUNK_SIZE)
        tag = TAG_FINAL if not nxt else TAG_MESSAGE
        ct = _nb.crypto_secretstream_xchacha20poly1305_push(
            state, pending, b"", tag)
        fout.write(LEN_PREFIX.pack(len(ct)))
        fout.write(ct)
        done += len(pending)
        if progress is not None:
            progress(done, total if total is not None else 0)
        if tag == TAG_FINAL:
            break
        pending = nxt
