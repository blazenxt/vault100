"""Keyfiles — a physical second factor for Vault100 vaults.

A keyfile is mixed into the Key Encryption Key via HKDF, so unlocking a
vault needs *something you know* (password) **and** *something you have*
(keyfile). Lose either one and the vault stays sealed.

Any file can serve as a keyfile (VeraCrypt-style): its contents are hashed
with BLAKE2b and the digest mixed into the KEK. Files created by
:func:`generate_keyfile` are simply 256 bits of fresh randomness with a
magic prefix — treat them like house keys:

* store them on a separate device (USB stick) when possible
* keep a backup copy somewhere safe — no keyfile, no decryption
"""

from __future__ import annotations

import hashlib
import os

KEYFILE_MAGIC = b"V100KEY1"
KEYFILE_BYTES = 32            # 256 bits of entropy in generated keyfiles
_MAX_KEYFILE = 16 * 1024 * 1024  # sanity cap when loading arbitrary files


class KeyfileError(Exception):
    """Raised when a keyfile cannot be created or loaded."""


def generate_keyfile(path: str, *, overwrite: bool = False) -> str:
    """Create a fresh random keyfile at *path*. Returns *path*."""
    if os.path.exists(path) and not overwrite:
        raise KeyfileError(f"refusing to overwrite existing file: {path}")
    with open(path, "wb") as f:
        f.write(KEYFILE_MAGIC + os.urandom(KEYFILE_BYTES))
    try:
        os.chmod(path, 0o400)  # read-only; keyfiles should not change
    except OSError:
        pass
    return path


def load_keyfile(path: str) -> bytes:
    """Return the 32-byte key digest for any keyfile.

    Recognises Vault100-generated keyfiles by magic, but accepts any file
    (hashes whatever bytes it contains, VeraCrypt-style).
    """
    try:
        with open(path, "rb") as f:
            data = f.read(_MAX_KEYFILE + 1)
    except OSError as e:
        raise KeyfileError(f"cannot read keyfile {path!r}: {e}") from None
    if not data:
        raise KeyfileError(f"keyfile {path!r} is empty")
    if len(data) > _MAX_KEYFILE:
        raise KeyfileError(f"keyfile {path!r} too large (>16 MiB)")
    if data.startswith(KEYFILE_MAGIC):
        data = data[len(KEYFILE_MAGIC):]
    # keyed BLAKE2b — chosen (not "person") so the exact same digest can be
    # reproduced by libsodium's crypto_generichash in the web edition.
    return hashlib.blake2b(data, digest_size=32,
                           key=b"Vault100-KF-v2").digest()


def identify(path: str) -> str:
    """Human-readable description of what kind of keyfile *path* is."""
    with open(path, "rb") as f:
        head = f.read(len(KEYFILE_MAGIC))
    return ("Vault100 keyfile" if head == KEYFILE_MAGIC
            else "arbitrary file (hashed as-is)")
