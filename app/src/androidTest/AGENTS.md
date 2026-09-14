# Purpose

Owns Android instrumentation tests executed on emulator/device.

# Ownership

- Tests under `app/src/androidTest/java/`

# Local Contracts

- Use instrumentation tests for integration checks that require Android runtime.
- Keep assertions focused on user-visible behavior and Android context wiring.

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

