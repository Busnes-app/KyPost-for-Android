# Android device-envelope v3 continuation plan

**Status:** Planned, not implemented. User requested this plan on 2026-09-15.
**Repo:** kypost-android
**Worktree:** Main checkout; documentation only. Implementation starts in a new worktree.
**Baseline:** Android `1fa836b07761f91af061eef5444e96cefdd78d75` (PRs #109–111 merged).
**Server contract:** [PR #199](https://github.com/Busness-app/KyPost-Server/pull/199), merged at `dc2a70eb3a5288be64dd5e08482844a80dfb8969`.
**Handoff:** Myslop `kypost-android-pgp-parity`, post #763.

## Objective and boundary

Prepare Android to authenticate device-envelope v3, validate its complete versioned keyring, persist it without losing prior material, and select historical decryption keys independently of the active signer. Preserve the existing biometric/SAS checks, legacy v2 behavior, plaintext cleanup, and intentional unpair/wipe semantics.

This plan has three independently reviewable native increments, followed by a production integration gate. Completing preparation does **not** advertise v3 capability or enable converted-account delivery. Server capability publication, revision/session-bound upload, generation-aware acknowledgement and stale-device send enforcement are separate prerequisites. Do not invent their HTTP fields or reuse the legacy boolean acknowledgement as proof of v3 enrollment.

The older live-relay checks remain outstanding. They do not block native fixture and disposable-emulator work, and passing those tests does not complete the live checks.

## Sources to pin before implementation

Read these files at the server merge above, not an arbitrary later working tree:

- [PGP_KEY_LIFECYCLE.md](https://github.com/Busness-app/KyPost-Server/blob/dc2a70eb3a5288be64dd5e08482844a80dfb8969/docs/PGP_KEY_LIFECYCLE.md): ring validation, device framing, persistence and rollout requirements. The larger lifecycle document still contains proposed work; implement the shipped v3 preparation contract only.
- [E2E_PGP.md](https://github.com/Busness-app/KyPost-Server/blob/dc2a70eb3a5288be64dd5e08482844a80dfb8969/docs/E2E_PGP.md): interoperability claims and activation gates.
- `testdata/device-envelope-v3.json`: public test-only scalars, exact plaintext, ECDH/HKDF/AAD and ciphertext vectors for v2/v3.
- `testdata/pgp-keyring-v1.json`: complete-ring and historical/hidden-recipient decryption fixtures.
- `backend/internal/cryptutil/device_envelope_v3_test.go` and `frontend/src/lib/deviceEnvelopeV3.test.ts`: independent framing references. Apply the TypeScript skill if reading the latter.

Copy shared JSON fixtures unchanged into Android test resources and record the source commit and checksums. Never put fixture scalars, IVs or keys into production defaults.

## Current code and consequences

| Area | Observed at Android baseline | Required change |
| --- | --- | --- |
| `pgp/DeviceEnvelope.kt` | Accepts v2 only; v2 domain is fixed in both HKDF and AAD | Explicit version selection; authenticate v3 without fallback to v2 |
| `pgp/SecretKeyRingMerge.kt` | Preserves legacy historical primary/subkey packets and current-first ordering | Retain for legacy input; JSON rings need their own exact inventory/active-member validation |
| `pgp/EnrollmentSession.kt` | Holds one wipeable armor collection | Hold one validated complete bundle; expose active signing separately from historical decrypt access |
| `pgp/PgpEncryptor.kt` | Own-key derivation/signing depend on collection order | Select the JSON ring's explicit active fingerprint; no historical fallback |
| `pgp/EnrollmentVault.kt` | Stores one IV/ciphertext pair; ignores `SharedPreferences.commit()` result; key regeneration clears prior storage | Make successful seal mean durable replacement; failure must preserve the old record and key |
| `pgp/DeviceEnrollmentActivity.kt` | Calls `vault.store`, then reports `SealOutcome.Sealed` | Propagate storage failure before ceremony success |
| `pgp/EnrollmentCeremony.kt` | Opens old vault, merges legacy material, seals, clears session/cache, then reports | Separate validated v3 import from legacy merge and network acknowledgement |
| `pgp/EnrollmentClients.kt`, `EnrollmentStateWorker.kt` | Legacy key publication and boolean enrollment report | Keep production v3 disabled until the server contract supplies generation-bound publication/acknowledgement |

Production paths above are under `app/src/main/java/org/kysecurity/mail/`. Read root, app, and nearest source-set AGENTS.md before implementation. Preserve the unrelated main-checkout `app/build.gradle.kts` modification, untracked original parity plan, and existing worktrees. No implementation was made while preparing this plan.

## Increment 1 — durable vault replacement

**First PR.** This prerequisite also protects current v2 enrollment. No v3 activation or session-format change.

**Files:** `EnrollmentVault.kt`, the sealer in `DeviceEnrollmentActivity.kt`, relevant `EnrollmentCeremony*Test`, `EnrollmentVaultTest`, `EnrollmentVaultReadFailureTest`, and owning production/instrumentation AGENTS.md.

- [ ] Reproduce persistence failure: the sealer must not return `Sealed`, report enrolled, enqueue a positive report, or install new session material after a failed write.
- [ ] Establish atomic replacement of the IV and ciphertext as one record. Prefer Android `AtomicFile` for the already AES-GCM-encrypted record if the existing preference API cannot provide the required failure semantics. Checking `commit()` alone is insufficient proof: a failed disk commit can still replace the in-process preference view.
- [ ] If moving the ciphertext record, read existing preference-backed vaults without rewriting on ordinary unlock. Commit the new record successfully before retiring the legacy copy. Crash/failure must leave a readable old or new complete record, never a mixed IV/ciphertext pair. Bound both formats before decoding.
- [ ] Preserve the existing per-use authenticated Keystore key. A present but unreadable/mismatched key or unreadable prior store must fail closed during replacement; `ensureKey()` must not regenerate over it. Audit preference-opening recovery behavior too. Only confirmed first enrollment may create fresh material automatically.
- [ ] Test cancellation and Activity destruction before authentication, during sealing, and after durable write. Once a write commits, retain that complete record; cancellation must not trigger a destructive rollback or premature network acknowledgement.
- [ ] Update intentional unpair/security-wipe cleanup for every retained storage location. Any migration recovery copy contains ciphertext only and remains discoverable by wipe.

**Acceptance:** storage fault injection and restart recovery prove the previous vault remains decryptable after an unsuccessful replacement. A successful replacement survives reopening the store. Real Keystore/biometric instrumentation proves protection is unchanged. Existing legacy enrollment and lifecycle tests pass.

## Increment 2 — pure v3 framing and keyring validation

**Second PR, after increment 1 merges.** Add tested native consumption primitives; leave live enrollment dispatch on v2.

**Files:** `DeviceEnvelope.kt`, `Sec1Point.kt` as needed, a small pure `PgpKeyring.kt`, `MemoryBudget.kt`, `DeviceEnvelopeTest`, new `PgpKeyringTest`, `MemoryBudgetTest`, and copied shared JSON resources. Reuse installed Bouncy Castle, JSON and JCA primitives; add no dependency.

- [ ] Make envelope version an explicit parsed value used by both HKDF and AAD. Keep the existing v2 vector byte-compatible. Reject unknown versions/algorithms and never retry a rejected v3 envelope as v2.
- [ ] For v3 enforce a 128 KiB UTF-8 serialized-envelope limit before JSON/base64 work, padded standard base64, a valid 65-byte uncompressed P-256 point, 12-byte IV, and ciphertext with a complete 16-byte GCM tag. Test malformed lengths, invalid points and trailing/ambiguous inputs.
- [ ] Pin exact ECDH output and HKDF key against shared vectors. HKDF uses the device's raw public point as salt and `kypost-device-envelope/v3` as info. AAD uses that domain and uint16BE UTF-8 byte lengths for exact device ID and active fingerprint. Device ID is nonempty, unchanged, at most 65,535 UTF-8 bytes; fingerprint is canonical uppercase hex of length 40 or 64. Bind expected identity/device values supplied independently of the ciphertext.
- [ ] Authenticate before parsing plaintext. Reject wrong device, fingerprint, domain, salt, point or tag; test the multibyte/pipe device ID in the fixture.
- [ ] Parse `kypost-pgp-keyring-v1` under its separate 128 KiB plaintext bound. Require correctly typed fields, positive safe-integer generation (at most 2^53−1), one matching active member, at most 16 primary members and 256 total primary/subkey fingerprints. Reject duplicate JSON members and fingerprint duplicates after case normalization, missing/extra inventory entries, unsupported formats and malformed UTF-8.
- [ ] Derive every member and subkey fingerprint from the actual packets. Require exactly one private ring per entry, complete unprotected private packets, and appropriate valid primary/subkey relationships; reject public-only, dummy/missing or still-passphrase-protected JSON private packets before performing any attacker-selected password KDF. Keep legacy parsing/limits on the legacy path rather than imposing new JSON rules on existing vaults.
- [ ] Preserve original validated JSON bytes, every private packet/certification/revocation, and optional revocation-certificate contents. Do not reconstruct storage from re-exported keys or invent certificate-merge behavior. Historical revoked/expired members remain available for old-message decryption; they do not become usable active signers.
- [ ] Account for ciphertext, plaintext, UTF-8/character buffers, JSON parser retention, extracted key material and old/new bundles in `MemoryBudget`. Bound all attacker-sized work before allocation; do not reduce existing legacy import capacity silently. Plaintext holders redact `toString()` and use explicit cleanup; document unavoidable transient JSON Strings rather than claiming they are wipeable.

**Acceptance:** unchanged shared vectors pass, negative framing/inventory cases fail closed, and Bouncy Castle decrypts both historical fixtures (including hidden recipient IDs). The v2 regression suite and minified runtime-class-name gates remain green.

## Increment 3 — complete-bundle session and local import

**Third PR, after increment 2 merges.** Prove end-to-end local durable import using injected transport/fixtures. Keep production v3 dispatch and capability publication off.

**Files:** `EnrollmentSession.kt`, `VaultOpenerAndroid.kt`, `EnrollmentCeremony.kt` or its extracted local import helper, `PgpDecryptor.kt`, `PgpEncryptor.kt`, `ClientEncryptedSender.kt`, `ClientEncryptedDraftSaver.kt`, relevant unit tests and `EnrollmentEnvelopeRoundTripTest`/vault instrumentation. Update nearest AGENTS.md contracts.

- [ ] Retain a single sealed complete bundle and a single unlock session. Add narrowly scoped access to all decryption members and the explicit active member. Reuse legacy current-first behavior only for legacy armor. Sweep all `EnrollmentSession.withKey` callers so none accidentally passes JSON to an armor parser or signs with the first historical member.
- [ ] Validate temporary material fully before touching the existing vault or session. Sequence local import as authenticate → validate entire ring → establish replacement safety → seal and durably store original bytes → clear/install session state from that committed bundle → mark local import complete. A future acknowledgement caller may run only after that point.
- [ ] Keep v3 bundles out of `mergeSecretKeyRings`. Equal active fingerprints or equal inventories do not prove equal private packets/certifications/revocations. Before the server replacement contract is available, permit fixture-driven fresh import and exact replay; refuse incomparable replacement without destroying the prior record. General conversion/retirement replacement is gated below, not implemented by guessing how to merge older backups.
- [ ] Derive own public key and signatures from the explicit active member for normal sends, Sent copies and encrypted drafts. Fail when the active member is unusable; never choose a historical key as a fallback. Historical decryption scans available matching private keys, including hidden-recipient cases.
- [ ] After process restart, reopen only from persistent sealed storage; decrypt historical mail and sign with the active member. Simulating a fresh session/store is the unit seam; use an actual process boundary or two-phase instrumentation for the restart claim.
- [ ] Test failed unlock, validation failure in any member, storage failure, duplicate/replayed import, cancellation and stale Activity callbacks. No partial session install and no acknowledgement before persistence. If cancellation occurs after commit, retain the durable complete record and leave any protocol acknowledgement pending.
- [ ] Ensure `EnrollmentStateWorker`/background enrollment probes cannot infer v3 completion from blob presence and emit a legacy positive acknowledgement for a prepared v3 record. Until the generation-bound server protocol exists, production transport never admits such records; tests use an explicit local completion seam, not a fabricated HTTP field.

**Acceptance:** fresh import containing history survives a real restart; old mail decrypts, new signatures and self-encryption use the active member, failed replacement leaves old mail readable, and a recording acknowledgement seam sees no premature call. No plaintext enters Room, logs or telemetry. Existing lock/wipe/unpair and v2 enrollment tests still pass.

## Production integration gate — separate future PR

Do not activate v3 merely because the three native increments pass.

- [ ] Obtain the merged server contract for supported-version publication, current snapshot/revision/generation metadata, delivery session binding, generation-aware acknowledgement and retry, and stale-device send rejection. Record exact PRs/commits before choosing Android request fields.
- [ ] Agree on authoritative replacement/history-preservation rules for legacy conversion and v3 retirement, including differing certifications/revocations and recovery of older backups. Until then, refuse unsafe/incomparable replacement and preserve prior material.
- [ ] Wire v3 into live enrollment only with those contracts. Preserve SAS comparison, bind to the original device/identity/session, and recheck before mutation. No active-key-only downgrade for converted accounts.
- [ ] Gate sends and self-encryption against current active fingerprint, generation and revocation state. Clear stale-device readiness until re-enrollment; do not claim offline generation metadata revokes exported keys.
- [ ] Validate the released Android artifact with a paired disposable relay/account, and coordinate with the server/Mac/Linux readiness gates before enabling account conversion.

## Verification and delivery for each native PR

Use a fresh worktree from updated `origin/main`; one bounded increment per PR. Demonstrate each bug regression failing before its fix, then run relevant checks. Update nearest DOX when behavior or verification changes. UI changes require STYLE_GUIDE.md and real instrumentation. Do not rewrite historical plans as if their old test counts describe this work.

Focused JVM entry points (add each new class when introduced):

```bash
./gradlew :app:testPlayDebugUnitTest \
  --tests '*DeviceEnvelopeTest*' --tests '*EnrollmentCeremony*' \
  --tests '*EnrollmentSessionTest*' --tests '*SecretKeyRingMergeTest*' \
  --tests '*MemoryBudgetTest*'
```

Before each PR, full required flavor gates:

```bash
./gradlew checkSigningSecretsAreNotInTheTree \
  checkExportedComponentsPlayDebug checkExportedComponentsGithubDebug checkExportedComponentsFdroidDebug \
  :app:testPlayDebugUnitTest :app:testGithubDebugUnitTest :app:testFdroidDebugUnitTest \
  :app:lintPlayDebug :app:lintGithubDebug :app:lintFdroidDebug \
  :app:assembleRelease \
  :app:checkRuntimeMatchedClassNamesPlayRelease \
  :app:checkRuntimeMatchedClassNamesGithubRelease \
  :app:checkRuntimeMatchedClassNamesFdroidRelease
```

Use a disposable verification signer for local release gates; these APKs are not production releases. Run affected real Keystore/storage/lifecycle tests on a disposable secure-lock emulator; run the current API 31/34/36 CI matrix, including F-Droid. Restart and fault-injection evidence must state what was actually exercised.

Open the PR ready for review and drive both CI and the independent security reviewer to green on the same head. Report exact tested commits, fixture provenance, storage failure evidence, and outstanding live checks to both `kypost-android-pgp-parity` and `kypost-pgp-punch-list`. Human merges; no automatic deployment or conversion.

## Still-outstanding live checks from the original parity work

- Encrypted draft save/storage/readback with protected To/Cc/Bcc/Subject/body/attachment; verify ciphertext in IMAP.
- Unenrolled no-transfer handoff and retained composer on return.
- Proton attachment/CID interoperability in both directions and changed-relay delta sync.
- Retirement/re-enrollment and historical mail on an actual paired environment.

No test relay/account or paired device has been supplied. Keep these unchecked until actual evidence exists. Planning and local fixtures do not resolve that blocker.
