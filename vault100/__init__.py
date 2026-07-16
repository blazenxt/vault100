"""Vault100 — maximum-security file encryption (v2).

Envelope-encrypted vaults: random per-file key wrapped by an
Argon2id-derived (+ optional keyfile) master key; XChaCha20-Poly1305
secretstream with optional AES-256-GCM cascade.
"""

from .crypto_core import (
    DEFAULT_PROFILE,
    KDF_PROFILES,
    VaultAuthError,
    VaultCancelled,
    VaultError,
    VaultFormatError,
    calibrate_profile,
    change_password,
    decrypt_file,
    decrypt_stream,
    encrypt_file,
    encrypt_stream,
    vault_info,
    verify_file,
)
from .keyfile import generate_keyfile, load_keyfile

__version__ = "2.0.24"
__all__ = [
    "DEFAULT_PROFILE",
    "KDF_PROFILES",
    "VaultAuthError",
    "VaultCancelled",
    "VaultError",
    "VaultFormatError",
    "calibrate_profile",
    "change_password",
    "decrypt_file",
    "decrypt_stream",
    "encrypt_file",
    "encrypt_stream",
    "generate_keyfile",
    "load_keyfile",
    "vault_info",
    "verify_file",
    "__version__",
]
