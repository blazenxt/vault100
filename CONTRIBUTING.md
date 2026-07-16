# Contributing to Vault100

Contributions are welcome — bug reports, ideas, docs, tests, and code.
Please read this once; it's short.

## Ground rules

1. **Security over sparkle.** Any change touching `web/vault-format.js`,
   `vault100/crypto_core.py`, `vault100/keyfile.py`, or header/KDF handling
   must keep **CLI ⇄ web ⇄ GUI byte-compatibility** and must be justified in
   the PR description.
2. **Zero knowledge is non-negotiable.** The web app must never transmit
   files, passphrases, keys, or vault bodies. Crypto stays in the Worker.
3. **No new runtime dependencies** for the web server (`web/server.mjs`
   stays zero-dependency Node ≥ 20). Python deps need a strong reason.
4. **Honest language.** Never claim "impossible to decrypt" — see the README.
5. Version bumps follow the project rule: normal changes bump the last digit
   (`v2.0.x`); a middle bump happens only when the maintainer calls it a
   *major upgrade*.

## Dev setup

```bash
git clone https://github.com/blazenxt/vault100.git
cd vault100
pip install -r requirements.txt        # PyNaCl, argon2-cffi, cryptography
# GUI needs tkinter: Debian/Ubuntu → sudo apt install python3-tk
```

## Run the tests

```bash
# fast KDF params keep the suite quick — never relax real seals in prod code
VAULT100_FAST_KDF=1 python3 -m pytest tests/test_crypto.py -q
```

## Run the web app locally

```bash
node web/server.mjs        # http://localhost:8080  — restart after edits (it preloads)
```

`node --check` every touched `web/*.js` before committing.

## Pull requests

* One change per PR; describe the *threat-model impact* if crypto-adjacent.
* Add/adjust tests for behavior changes; keep the suite green.
* Keep the house style: typewriter lean, comments where the "why" hides.

By contributing you agree your code is licensed under the project's MIT license.
