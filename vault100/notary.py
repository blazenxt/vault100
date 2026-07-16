"""The notary — ed25519 endorsements for Vault100 vaults.

A *seal* (secret signing key) endorses a vault; anyone holding the
matching *stamp* (public key) can attest that the vault truly came from
the seal-bearer — unforgeable, undeniable, and completely offline.

File formats (little-endian; byte-parity with web/worker.js)::

    .v100seal   "V100SEAL1" | 32-byte ed25519 seed            (KEEP SECRET)
    .v100stamp  "V100STAMP1" | 32-byte ed25519 public key     (share freely)
    .v100sig    "V100SIG1" | u32 epoch | 32-byte pk | 64-byte signature

The signature is plain detached ed25519 over the vault file bytes —
deterministic, so the desk CLI and the web counter stamp byte-identical
endorsements of the same vault with the same seal.
"""

from __future__ import annotations

import os
import time

import nacl.exceptions
import nacl.signing

from .crypto_core import VaultError

SEAL_MAGIC = b"V100SEAL1"
STAMP_MAGIC = b"V100STAMP1"
SIG_MAGIC = b"V100SIG1"
SEAL_EXT = ".v100seal"
STAMP_EXT = ".v100stamp"
SIG_EXT = ".v100sig"
SEED_BYTES = 32
PK_BYTES = 32
SIG_BYTES = 64
SIGFILE_BYTES = 8 + 4 + PK_BYTES + SIG_BYTES   # 108


class NotaryError(VaultError):
    """Bent seals, forged stamps, or endorsements that do not hold."""


def _atomic_write(path: str, data: bytes, overwrite: bool) -> None:
    if os.path.exists(path) and not overwrite:
        raise NotaryError(f"{path} already exists — refusing to overwrite")
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    try:                                    # best effort, like the keyfile press
        os.chmod(path, 0o600)
    except OSError:
        pass


def fingerprint(pk: bytes) -> str:
    """Short public fingerprint for receipts: 12 lowercase hex chars."""
    if len(pk) != PK_BYTES:
        raise NotaryError("a stamp is 32 bytes, not more, not less")
    return pk.hex()[:12]


# ---------------------------------------------------------------------------
# Mint / load
# ---------------------------------------------------------------------------

def mint_seal(path: str, *, overwrite: bool = False) -> dict:
    """Mint a seal + stamp pair; the stamp lands beside the seal."""
    seed = nacl.signing.SigningKey.generate()
    pk = bytes(seed.verify_key)
    stamp_path = path[:-len(SEAL_EXT)] + STAMP_EXT \
        if path.endswith(SEAL_EXT) else path + STAMP_EXT
    _atomic_write(path, SEAL_MAGIC + bytes(seed), overwrite)
    try:
        _atomic_write(stamp_path, STAMP_MAGIC + pk, overwrite)
    except Exception:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise
    return {"seal": path, "stamp": stamp_path, "fingerprint": fingerprint(pk)}


def load_seal(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read(64)
    except OSError as e:
        raise NotaryError(f"cannot read seal: {e}") from e
    if not data.startswith(SEAL_MAGIC):
        raise NotaryError("not a Vault100 seal (missing V100SEAL1 stamp)")
    seed = data[len(SEAL_MAGIC):]
    if len(seed) != SEED_BYTES:
        raise NotaryError("seal is bent — wrong length")
    return seed


def load_stamp(path: str) -> bytes:
    try:
        with open(path, "rb") as f:
            data = f.read(64)
    except OSError as e:
        raise NotaryError(f"cannot read stamp: {e}") from e
    if not data.startswith(STAMP_MAGIC):
        raise NotaryError("not a Vault100 stamp (missing V100STAMP1 mark)")
    pk = data[len(STAMP_MAGIC):]
    if len(pk) != PK_BYTES:
        raise NotaryError("stamp is bent — wrong length")
    return pk


# ---------------------------------------------------------------------------
# Endorse / attest
# ---------------------------------------------------------------------------

def endorse_bytes(data: bytes, seed: bytes, *, epoch: int | None = None) -> bytes:
    """Vault bytes + seal seed → a detached .v100sig endorsement file."""
    if len(seed) != SEED_BYTES:
        raise NotaryError("a seal is a 32-byte seed")
    sk = nacl.signing.SigningKey(seed)
    sig = sk.sign(data).signature
    ts = int(time.time()) if epoch is None else int(epoch)
    return (SIG_MAGIC + ts.to_bytes(4, "little")
            + bytes(sk.verify_key) + sig)


def inspect_sig(blob: bytes) -> dict:
    if len(blob) != SIGFILE_BYTES:
        raise NotaryError(
            f"a Vault100 endorsement is {SIGFILE_BYTES} bytes on the nose — "
            "this one is torn")
    if not blob.startswith(SIG_MAGIC):
        raise NotaryError("not a Vault100 endorsement (missing V100SIG1)")
    return {
        "epoch": int.from_bytes(blob[8:12], "little"),
        "pk": bytes(blob[12:44]),
        "sig": bytes(blob[44:108]),
    }


def attest_bytes(data: bytes, blob: bytes, *,
                 stamp_pk: bytes | None = None) -> dict:
    """Does the endorsement hold for these vault bytes?

    With *stamp_pk* given, the endorsement must also come from exactly
    that seal-bearer. Returns a verdict dict; raises NotaryError only for
    malformed paper, never for a mere refusal."""
    parts = inspect_sig(blob)
    if stamp_pk is not None and parts["pk"] != stamp_pk:
        return {**parts, "valid": False,
                "reason": "endorsed by a DIFFERENT seal than the stamp presented",
                "fingerprint": fingerprint(parts["pk"])}
    try:
        nacl.signing.VerifyKey(parts["pk"]).verify(data, parts["sig"])
        return {**parts, "valid": True, "reason": "endorsement holds",
                "fingerprint": fingerprint(parts["pk"])}
    except nacl.exceptions.BadSignatureError:
        return {**parts, "valid": False,
                "reason": "the signature does NOT hold — tampered, swapped, "
                          "or signed over other paper",
                "fingerprint": fingerprint(parts["pk"])}


# ---------------------------------------------------------------------------
# File conveniences (CLI/GUI counters)
# ---------------------------------------------------------------------------

def endorse_file(vault: str, seal_path: str, out: str | None = None) -> dict:
    with open(vault, "rb") as f:
        data = f.read()
    blob = endorse_bytes(data, load_seal(seal_path))
    out = out or vault + SIG_EXT
    _atomic_write(out, blob, overwrite=True)
    parts = inspect_sig(blob)
    return {"sig": out, "epoch": parts["epoch"],
            "fingerprint": fingerprint(parts["pk"])}


def attest_file(vault: str, sig_path: str,
                stamp_path: str | None = None) -> dict:
    with open(vault, "rb") as f:
        data = f.read()
    with open(sig_path, "rb") as f:
        blob = f.read()
    stamp_pk = load_stamp(stamp_path) if stamp_path else None
    return attest_bytes(data, blob, stamp_pk=stamp_pk)
