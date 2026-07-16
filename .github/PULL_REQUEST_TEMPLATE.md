## What & why

<!-- one change per PR. What does it do, who does it help? -->

## Threat-model impact

<!-- crypto-adjacent? describe the impact, or write "none" -->
<!-- CLI ⇄ web ⇄ GUI byte-compatibility preserved? -->

## Checks

- [ ] `VAULT100_FAST_KDF=1 python3 -m pytest tests/test_crypto.py -q` is green
- [ ] `node --check` passes on every touched `web/*.js`
- [ ] no new runtime dependency for `web/server.mjs`
- [ ] secrets never leave the client (zero-knowledge rule intact)
- [ ] version bumped per project rule (last digit for normal changes)
