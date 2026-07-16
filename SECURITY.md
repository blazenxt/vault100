# Security Policy

Vault100 is security software — reports are taken seriously and handled quietly.

## Supported versions

| Version | Supported |
|---|---|
| latest `v2.0.x` release | ✅ |
| older v2.0.x | ⚠️ upgrade first — fixes ship in the newest patch |
| v1 vaults / `master` v1 code | ❌ (v1 files are decrypt-only in v2) |

## Reporting a vulnerability

**Please do not open a public issue for security bugs.**

1. Use GitHub **Private vulnerability reporting** (the repo's *Security → Advisories*
   tab), or
2. If that is unavailable, open a minimal public issue asking for a private
   contact — do **not** include details, PoCs, or secrets.

You will get an acknowledgement within ~72 hours and a fix or a clear
assessment as quickly as the problem allows. Credit in the release notes is
yours if you want it.

## What counts and what doesn't

**In scope**

* Any way to read plaintext, keys, or metadata from a `.v100` vault without
  the passphrase/keyfile.
* Cross-implementation divergence that weakens security (web ⇄ CLI ⇄ GUI).
* Browser-side secret leakage (memory not wiped, secrets in logs/DOM that
  survive the sweep).
* Dependency/supply-chain issues in `web/vendor/` or `requirements.txt`.
* The zero-knowledge server sending anything beyond static files.

**Out of scope** (by design, never promised)

* Attacks requiring the victim's passphrase or keyfile.
* Compromised devices (malware, keyloggers, hostile extensions).
* Side channels inherent to shared hardware (Spectre-class).
* Deniability/plausible-deniability claims — Vault100 makes none.

## The straight talk (also in the README)

No honest software can promise "impossible to decrypt." Vault100 layers
*independent* defenses — XChaCha20-Poly1305 (+ optional AES-256-GCM cascade),
Argon2id memory-hard derivation, optional keyfiles — so a failure anywhere
else still leaves data sealed. The variable you control is your passphrase;
the built-in meter exists to help you choose well.
