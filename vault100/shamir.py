"""The quorum press — Shamir M-of-N secret sharing over GF(2^8).

        split_secret(secret, n, m)  →  N binary slips, any M reopen
        join_secret(slips)          →  the secret, or ShareError

Binary slip layout (little-endian, byte-parity with web/vault-format.js)::

    0   6   magic "V100S1"
    6   5   press id  (random, identical for all slips of one pressing)
    11  1   threshold M
    12  1   count N
    13  1   x coordinate (1..255)
    14  2   secret length L (le)
    16  L   y-bytes   (each polynomial evaluated at x)
    16+L 4  crc32 (zlib) of everything above, le

Text slips ("armor for shares", tolerates surrounding junk lines)::

    -----BEGIN V100 SHARE 3 OF 5-----
    <base64 of the binary slip, wrapped at 64 columns>
    -----END V100 SHARE-----

Security notes
--------------
*  Each byte of the secret rides its own random polynomial of degree M-1
   over GF(2^8); with fewer than M points every byte value stays equally
   likely (Shamir's information-theoretic guarantee, per byte).
*  The crc32 is a clerk's checksum against typos and torn paper — it is
   NOT an authentication code.  Anyone holding M untampered slips learns
   the secret; guard slips like keys.
*  Secrets up to 65535 bytes: passphrases and keyfiles, not documents
   (seal documents into .v100 vaults instead).
"""

from __future__ import annotations

import base64
import os
import re
import zlib

from .crypto_core import VaultError

SHARE_MAGIC = b"V100S1"
SHARE_BEGIN_RE = re.compile(
    r"-----BEGIN V100 SHARE\s+(\d+)\s+OF\s+(\d+)-----")
SHARE_BEGIN = "-----BEGIN V100 SHARE "          # followed by "k OF n-----"
SHARE_END = "-----END V100 SHARE-----"
SHARE_COLS = 64
SHARE_EXT = ".v100s"

MIN_THRESHOLD = 2
MAX_SHARES = 255
MAX_SECRET = 0xFFFF
_PRESS_BYTES = 5
_OVERHEAD = 6 + _PRESS_BYTES + 1 + 1 + 1 + 2 + 4   # header + crc


class ShareError(VaultError):
    """Slips are damaged, mixed, or too few for the quorum."""


# ---------------------------------------------------------------------------
# GF(2^8): AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b), generator 3.
# ---------------------------------------------------------------------------

_EXP = [0] * 512
_LOG = [0] * 256
_x = 1
for _i in range(255):
    _EXP[_i] = _x
    _LOG[_x] = _i
    _x2 = _x << 1
    if _x2 & 0x100:
        _x2 ^= 0x11B
    _x = _x2 ^ _x                       # multiply by 3 = (x*2) ^ x
for _i in range(255, 512):
    _EXP[_i] = _EXP[_i - 255]
assert _LOG[1] == 0 and _x == 1, "generator 3 must have order 255"


def gf_mul(a: int, b: int) -> int:
    if a == 0 or b == 0:
        return 0
    return _EXP[_LOG[a] + _LOG[b]]


def gf_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF inverse of zero")
    return _EXP[255 - _LOG[a]]


def _mul_table(x: int) -> bytes:
    """Table t such that t[b] == gf_mul(b, x) — the hot loop's friend."""
    t = bytearray(256)
    if x:
        lx = _LOG[x]
        for b in range(1, 256):
            t[b] = _EXP[_LOG[b] + lx]
    return bytes(t)


# ---------------------------------------------------------------------------
# Binary slip construction / inspection
# ---------------------------------------------------------------------------

def _pack_slip(press: bytes, m: int, n: int, x: int, y: bytes) -> bytes:
    head = (SHARE_MAGIC + press + bytes((m, n, x))
            + bytes((len(y) & 0xFF, len(y) >> 8)))
    body = head + y
    return body + zlib.crc32(body).to_bytes(4, "little")


def inspect_slip(slip: bytes) -> dict:
    """Validate one binary slip; raise ShareError on any damage."""
    if len(slip) < _OVERHEAD + 1:
        raise ShareError("slip is too short — the press never struck this")
    if slip[:6] != SHARE_MAGIC:
        raise ShareError("not a Vault100 slip (missing V100S1 stamp)")
    length = slip[14] | (slip[15] << 8)
    if len(slip) != _OVERHEAD + length:
        raise ShareError("slip is torn — length stamp and body disagree")
    want = int.from_bytes(slip[-4:], "little")
    if zlib.crc32(slip[:-4]) != want:
        raise ShareError(
            "slip checksum mismatch — a character was retyped wrong "
            "(or the paper was doctored)")
    m, n, x = slip[11], slip[12], slip[13]
    if x == 0 or m < MIN_THRESHOLD or n > MAX_SHARES or m > n:
        raise ShareError("slip bears an impossible quorum stamp")
    return {
        "press": slip[6:11], "m": m, "n": n, "x": x,
        "length": length, "y": bytes(slip[16:16 + length]),
    }


# ---------------------------------------------------------------------------
# Split / join
# ---------------------------------------------------------------------------

def split_secret(secret: bytes, n: int, m: int) -> list[bytes]:
    """Break *secret* into *n* slips; any *m* of them reprint it."""
    if not isinstance(secret, (bytes, bytearray)):
        raise TypeError("secret must be bytes")
    secret = bytes(secret)
    if not (MIN_THRESHOLD <= m <= n <= MAX_SHARES):
        raise ShareError(
            f"need {MIN_THRESHOLD} ≤ quorum ≤ slips ≤ {MAX_SHARES}")
    if not (1 <= len(secret) <= MAX_SECRET):
        raise ShareError(
            f"the press takes 1–{MAX_SECRET} bytes — "
            "seal larger payloads as .v100 vaults and split a passphrase")

    press = os.urandom(_PRESS_BYTES)
    length = len(secret)
    # one random polynomial of degree m-1 per secret byte:
    #   p(x) = secret[b] + c1[b]·x + c2[b]·x² + …
    coeffs = [secret] + [os.urandom(length) for _ in range(m - 1)]
    slips = []
    for x in range(1, n + 1):
        tab = _mul_table(x)
        acc = bytearray(coeffs[m - 1])
        for k in range(m - 2, -1, -1):                # Horner
            ck = coeffs[k]
            for b in range(length):
                acc[b] = tab[acc[b]] ^ ck[b]
        slips.append(_pack_slip(press, m, n, x, bytes(acc)))
    del coeffs          # random coefficients mirror no secret by design
    return slips


def join_secret(slips: list[bytes]) -> bytes:
    """Reprint the secret from ≥ M slips of one pressing."""
    if not slips:
        raise ShareError("no slips presented")
    parts = [inspect_slip(s) for s in slips]
    press, m, n, length = (parts[0][k] for k in ("press", "m", "n", "length"))
    for p in parts[1:]:
        if p["press"] != press:
            raise ShareError(
                "these slips come from different pressings — "
                "they were never one secret")
        if p["m"] != m or p["n"] != n or p["length"] != length:
            raise ShareError("the slips disagree about their own quorum")
    seen = set()
    uniq = []
    for p in parts:
        if p["x"] in seen:
            continue                      # same slip twice — count it once
        seen.add(p["x"])
        uniq.append(p)
    if len(uniq) < m:
        raise ShareError(
            f"the quorum press needs {m} different slips — "
            f"only {len(uniq)} presented")
    use = uniq[:m]

    # Lagrange at x=0 in characteristic two: λ_j = Π_{k≠j} x_k·(x_k⊕x_j)⁻¹
    tabs = []
    for j, pj in enumerate(use):
        lam = 1
        for k, pk in enumerate(use):
            if k != j:
                lam = gf_mul(lam, gf_mul(pk["x"], gf_inv(pk["x"] ^ pj["x"])))
        tabs.append(_mul_table(lam))

    out = bytearray(length)
    for tab, p in zip(tabs, use):
        y = p["y"]
        for b in range(length):
            out[b] ^= tab[y[b]]
    return bytes(out)


# ---------------------------------------------------------------------------
# Text slips (base64 armor)
# ---------------------------------------------------------------------------

def encode_slip(slip: bytes) -> str:
    """One binary slip → its text slip. k/n read from the slip itself."""
    info = inspect_slip(slip)
    b64 = base64.b64encode(slip).decode("ascii")
    lines = [f"{SHARE_BEGIN}{info['x']} OF {info['n']}-----"]
    lines += [b64[i:i + SHARE_COLS]
              for i in range(0, len(b64), SHARE_COLS)]
    lines.append(SHARE_END)
    return "\n".join(lines) + "\n"


def decode_slips(text: str) -> list[bytes]:
    """All text slips found in *text* (junk around/between tolerated)."""
    found = []
    pos = 0
    while True:
        m = SHARE_BEGIN_RE.search(text, pos)
        if m is None:
            break
        end = text.find(SHARE_END, m.end())
        if end < 0:
            raise ShareError("a slip's closing stamp is missing")
        body = re.sub(r"\s+", "", text[m.end():end])
        try:
            slip = base64.b64decode(body, validate=True)
        except Exception:
            raise ShareError(
                f"slip {m.group(1)} of {m.group(2)}: base64 is damaged")
        inspect_slip(slip)                # crc + shape, with x/n stamps
        info = inspect_slip(slip)
        if info["x"] != int(m.group(1)) or info["n"] != int(m.group(2)):
            raise ShareError(
                "slip's title line and stamped number disagree — doctored?")
        found.append(slip)
        pos = end + len(SHARE_END)
    if not found:
        raise ShareError("no Vault100 slips found in that text")
    return found


def split_to_text(secret: bytes, n: int, m: int) -> list[str]:
    return [encode_slip(s) for s in split_secret(secret, n, m)]


def join_from_text(texts) -> bytes:
    """From one blob of text (or a list of texts) → the secret."""
    if isinstance(texts, str):
        texts = [texts]
    slips = []
    for t in texts:
        slips.extend(decode_slips(t))
    return join_secret(slips)


def press_id_of(slip: bytes) -> str:
    """Short hex press id for receipts and UI chrome."""
    return inspect_slip(slip)["press"].hex()
