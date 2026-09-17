# Device envelope v3: live enrollment and generation-gated sends

**Status:** in progress. Fourth increment of
[2026-09-15-device-envelope-v3.md](2026-09-15-device-envelope-v3.md), whose production
integration gate this plan closes on the Android side.

**Server contract of record** (all merged to KyPost-Server `main`):

| Item | PR | Merge commit |
|---|---|---|
| v3 framing and shared vectors | #199 | `dc2a70eb3a5288be64dd5e08482844a80dfb8969` |
| capability publication (`envelopeVersions`) | #201 | `949be605` |
| bound delivery, generation-aware acknowledgement, stale-device send gate | #210 | `36cc6d6dc40f` |
| browser v3 ceremony for converted accounts | #212 | `c9c1e5e2c32f` |

Read `docs/E2E_PGP.md` and `docs/PGP_KEY_LIFECYCLE.md` at `a1b0c43` (server main when this plan
was written). No field below is invented; each is quoted from the handler or its tests.

## Contract the client implements

- `POST /api/pgp/device/enrollment-key` body `{"publicKey": <base64 SEC1>, "envelopeVersions": [2, 3]}`.
  Omitting the list resets the claim to `[2]`, and the browser then refuses to seal v3.
- `GET /api/pgp/device/envelope` 200 body: `envelope` (string), `version` (2|3), `fingerprint`
  (uppercase hex), `materialGeneration` (absent on a legacy account), `pgpRevision`, `keyring`
  (`{version, materialGeneration, primaryFingerprints, keyFingerprints}` or `null`), `publicKey`
  (armored account key). 404 means never sealed or expired (7 days), as before.
- `POST /api/pgp/device/enrollment-state`: `{"encryptionEnrolled": false}` forgets the delivery
  record. `{"encryptionEnrolled": true}` alone is accepted only on a legacy account. A keyring
  record is acknowledged with `{"encryptionEnrolled": true, "envelopeVersion": 3,
  "materialGeneration": <n>, "fingerprint": <hex>}`; the server matches it against the delivery it
  recorded for this device and answers 409 `{"pgpStateChanged": true, ...}` on any mismatch,
  recording nothing. 409 is never retried: the same claim cannot become true.
- `POST /api/mail/send-pgp` takes `materialGeneration` (required on a converted account) and
  answers 409 `{"pgpStateChanged": true}` when the generation moved, or 409
  `{"reenrollmentRequired": true}` when this device is not enrolled at the current generation.
- Registration's `encryptionEnrolled` pointer is unchanged and never carries v3 state.

## Increment scope (one PR)

1. **Publish `[2, 3]`.** Native complete-ring persistence checks passed in #112/#115/#116, which
   is the server's stated condition for advertising v3.
2. **Open v3 live.** `parseDeviceEnvelope` admits `{2, 3}`. A v3 envelope requires the fetch's
   delivery metadata (`version == 3`, `materialGeneration`, `keyring`) and goes through
   `importKeyring` with the AAD fingerprint. Before sealing, the parsed ring must match the
   delivery: same generation, same active fingerprint, same member set and same inventory. A
   mismatch is `FailureReason.KEYRING_REJECTED`; nothing is sealed.
3. **Acknowledge with metadata.** `EnrollmentTransport.reportEnrolled(Boolean)` becomes
   `report(EnrollmentReport)`: `NotEnrolled`, `Legacy`, or `Keyring(generation, fingerprint)`.
   The ceremony reports `Keyring` after `onLocalComplete`. The worker needs the same values
   without opening the vault, so the sealer stores them beside the record (`EnrollmentVault`
   plain preferences, cleared with the record and on destroy). They are public data: the
   server lists both on the owner's device page.
4. **Gate sends.** `ClientEncryptedMessage.materialGeneration` comes from the held keyring and
   is sent as `materialGeneration`; the relay maps the two new 409 markers to user-facing
   messages that name re-enrollment.
5. **Retire `legacyReportValue`.** `ENROLLED_KEYRING` reports its acknowledgement or nothing.

Out of scope, still gated server-side: conversion or retirement replacement of a different
ring already on the device (`RefusedIncomparable` stays), ring merging, readback.

## Verification

- JVM: `EnrollmentClientsTest`, `EnrollmentCeremonyKeyringTest` (new), `EnrollmentReportOutcomeTest`,
  `EnrollmentStatusTest`, `KeyringImportTest`, `ClientEncryptedSenderTest`, `RelayMailSourceTest`.
  Each new behaviour is shown red before green.
- Instrumentation: `EnrollmentVaultTest` gains acknowledgement storage and its removal on
  `destroy()`; run on the disposable API 36 emulator.
- Full three-flavour gates and the release build with the disposable signer before opening the PR.
- Not claimed: a live relay drill. Nothing here has been exercised against a real KySignOn or
  a converted account; that remains the human gate from the parent plan.
