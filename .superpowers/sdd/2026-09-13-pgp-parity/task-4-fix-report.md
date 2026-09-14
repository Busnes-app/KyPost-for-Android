# Task 4 fix report: owned decrypted attachment operations

## Outcome

- Downloads now receive an owned snapshot allocated after confirmation and before the executor
  hop. `OwnedAttachmentSave` admits one operation, refuses stale lifecycle callbacks and concurrent
  saves, preserves an authorized write through lock/destroy, and wipes/releases its snapshot on
  completion or rejected scheduling.
- The save call passes the raw MIME part name and type. `attachmentDownloadMetadata` resolves the
  allowlisted type before sanitising the display name, so `invoice.pdf` plus
  `application/octet-stream` becomes `invoice.pdf` plus `application/pdf`.
- The decrypted attachment cap is 4 MiB. The 128 MiB read model now explicitly counts 4 MiB retained
  parts, 2 MiB decode growth, one 4 MiB save snapshot, and one 4 MiB tap-to-open snapshot. The read
  peak is exactly 128 MiB; the 3 MiB inline-image budget is unchanged.
- Nearest production and JVM-test DOX contracts describe the sink ordering and lifecycle owner.

## Verification

- Focused JVM tests:
  `./gradlew :app:testFdroidDebugUnitTest --tests 'org.kysecurity.mail.security.OwnedAttachmentSaveTest' --tests 'org.kysecurity.mail.EmailDetailActivityTest' --tests 'org.kysecurity.mail.MemoryBudgetTest'`
  — **BUILD SUCCESSFUL**.
- Deliberate break: changed `OwnedAttachmentSave.admit` to retain the source rather than `copyOf()`;
  `OwnedAttachmentSaveTest.snapshotSurvivesCleanupAndIsAlwaysWipedBeforeAnotherAdmission` failed at
  its original-byte assertion. Restored `copyOf()` and the focused run passed.
- `:app:lintFdroidDebug` — passed.
- `:app:checkRuntimeMatchedClassNamesFdroidRelease` — passed after R8 produced minified release
  output. `assembleFdroidRelease` then stopped at packaging because release signing variables are
  unavailable; compilation, R8, lint-vital, and the requested runtime gate had already passed.
- API 36 emulator attempt:
  `:app:connectedFdroidDebugAndroidTest` limited to `AttachmentDownloadCleanupTest` built and launched,
  but all three existing tests failed in `clearDownloadsAndLedger` before their test bodies because
  this emulator reports `Unknown URL content://media/external/downloads` and lacks
  `/sdcard/Android`. No product assertion ran.

## Concerns

- The configured emulator cannot verify the Downloads provider path. The deterministic ownership,
  metadata boundary, and exact heap arithmetic are covered on the JVM.
- A real signed F-Droid release package was not produced because signing material is intentionally
  absent from the worktree.
