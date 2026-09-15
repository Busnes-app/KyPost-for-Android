# Purpose

Owns Android instrumentation tests executed on emulator/device.

# Ownership

- Tests under `app/src/androidTest/java/`

# Local Contracts

- Use instrumentation tests for integration checks that require Android runtime.
- Keep assertions focused on user-visible behavior and Android context wiring.
- `ComposeEncryptedDraftHandoffTest` verifies that saves and browser launches retain the composition
  and attachments on both success and failure, and that consent names visible address metadata.
- Activity fixtures must release runtime graphs they initialize after their scenarios close.
  A cached `MailRuntime` repository retains its DAO across later database-wipe tests; invalidate
  that graph in teardown while leaving `DataRuntime` and its open database owned by the suite.
- Prompt lifecycle tests must await the visible system prompt before recreating its Activity,
  then assert the replacement regains window focus. Request registration alone precedes window
  attachment; API 31 SystemUI can strand a window if cancelled during that interval.

# Work Guidance

- Add instrumentation coverage only when JVM tests cannot validate the behavior.
- Keep emulator/device setup assumptions minimal and explicit.

# Verification

- Run connected Android tests when instrumentation changes are made.
- `EnrollmentVaultReadFailureTest` injects a recoverable lazy preference failure over a legacy
  preference record, then checks the Android opener, the key guard, and recovery.
  `EnrollmentVaultTest` covers the file record: fault injection makes the pending path a directory
  so a replacement fails before the rename, then proves the previous record and key survive; a
  successful replacement is re-read by a fresh instance in the same process.
  `EnrollmentVaultCrashDurabilityTest` and `EnrollmentKeyringCrashDurabilityTest` are two phases
  each around a real kernel crash, driven only by `scripts/vault-crash-check.sh` (one crash cycle
  per record kind, since both share the vault file) on a rootable emulator with the CI PIN; they
  skip themselves unless the script passes `crashCheck`. The keyring pair seals the shared fixture
  ring under a fixed test-only AES key, then after boot reopens it from storage alone, decrypts
  both historical fixtures and signs with the active member; `src/androidTest/resources/` carries
  that fixture copy. `EnrollmentKeyringRecordTest` pins the record format byte and that a keyring
  record probes as enrolled locally with a false legacy report value. `DeviceEnrollmentSealLifecycleTest`
  recreates the Activity while the seal prompt is visible and proves cancellation keeps the
  previous record. `ReadOutcomeActivityTest`
  checks accepted and rejected attachment ownership through the real renderer and confirms that
  unchecked signature notices remain visible without a resolved sender. Both Activity tests
  require an unlocked app; the vault opener also requires a secure device lock screen.

# Child DOX Index

- No child AGENTS.md files.

