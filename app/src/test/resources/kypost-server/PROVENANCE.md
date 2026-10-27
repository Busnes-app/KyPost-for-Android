# Shared fixtures from KyPost-Server

Copied unchanged from https://github.com/Busnes-app/KyPost-Server at commit
`dc2a70eb3a5288be64dd5e08482844a80dfb8969` (merge of PR #199), `testdata/` directory.
Every scalar, IV and key in them is public test data; none may appear in production defaults.

| File | SHA-256 |
| --- | --- |
| `device-envelope-v3.json` | `0ce8d5ac20ec94bcc35facff6e76fcf78ec0d66f666aabc2dcef1965408e9c3a` |
| `pgp-keyring-v1.json` | `bba7d8fde4206be91e57a4953b3b56ff915ecb24f9a0f581b7098bdc6dfcb7cc` |
| `hpke-cfrg-p256-aes256.json` | `a9d0c155b22d18e647f790594a9494e62ac8999f3b0b0f219f0e31f6085b865a` |

`hpke-cfrg-p256-aes256.json` is from commit `fb5c282f94d8fcc3bfdbb174628da118e63db811`. Its `vector`
is the CFRG entry for mode 0 / KEM 16 / KDF 1 / AEAD 2 of
`https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json`
(SHA-256 `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`), re-checked
against that upstream file as the only matching entry, unmodified, on 2026-10-27.

Independent framing references at the same commit, not copied:
`backend/internal/cryptutil/device_envelope_v3_test.go` and
`frontend/src/lib/deviceEnvelopeV3.test.ts`. `FixtureProvenanceTest` pins the checksums.
