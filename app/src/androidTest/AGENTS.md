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
- `EnrollmentVaultReadFailureTest` injects a recoverable lazy preference failure while retaining
  the real stored ciphertext, then checks the Android opener and recovery. `ReadOutcomeActivityTest`
  checks accepted and rejected attachment ownership through the real renderer. Both Activity tests
  require an unlocked app; the vault opener also requires a secure device lock screen.

# Child DOX Index

- No child AGENTS.md files.

