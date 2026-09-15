# Shared fixtures from KyPost-Server

Copied unchanged from https://github.com/Busness-app/KyPost-Server at commit
`dc2a70eb3a5288be64dd5e08482844a80dfb8969` (merge of PR #199), `testdata/` directory.
Every scalar, IV and key in them is public test data; none may appear in production defaults.

| File | SHA-256 |
| --- | --- |
| `device-envelope-v3.json` | `0ce8d5ac20ec94bcc35facff6e76fcf78ec0d66f666aabc2dcef1965408e9c3a` |
| `pgp-keyring-v1.json` | `bba7d8fde4206be91e57a4953b3b56ff915ecb24f9a0f581b7098bdc6dfcb7cc` |

Independent framing references at the same commit, not copied:
`backend/internal/cryptutil/device_envelope_v3_test.go` and
`frontend/src/lib/deviceEnvelopeV3.test.ts`. `FixtureProvenanceTest` pins the checksums.
