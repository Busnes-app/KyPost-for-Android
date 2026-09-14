# Task 7 report: encrypted delta rows

**Repo:** kypost-android
**Worktree:** /home/yoshi/busness.app/kypost-android/.claude/worktrees/pgp-parity (branch worktree-pgp-parity)

## Outcome

- Added a delta-sync regression with bodyless encrypted `new` and `updated` rows.
- Both rows retain `pgpEncrypted` and `pgpSigned`, and neither fabricates a body.
- The wire classifications remain authoritative: only the `updated` row appears in
  `updatedMessageIds`; the `new` row remains a normal message outside that set.
- No runtime change was needed. The existing parser already preserves these semantics.
- The DOX pass found no contract update to make because this change only adds coverage for existing
  behavior.

## Verification

- Focused PlayDebug sync surface:

  `./gradlew :app:testPlayDebugUnitTest --tests "org.kysecurity.mail.mail.RelayMailSourceTest" --tests "org.kysecurity.mail.mail.MailRepositoryTest" --tests "org.kysecurity.mail.mail.RelayModelsSerializationTest"`

  **PASS** after restoring the deliberate mutation.
- Mutation proof: changed the `new` row's `pgpEncrypted` fixture value to false and ran
  `RelayMailSourceTest.deltaPoll_keepsEncryptedRowsFlagsWithoutBodies`. It failed at the encrypted
  flag assertion. Restored the real fixture before the final green run.
- `git diff --check`: **PASS**.

## Live relay

Not run. No live relay carrying the cache change is available, so the decrypt-button and removed-row
paths were not fabricated or claimed.

## Concerns

The JVM regression proves parsing and delta classification. The end-to-end refresh, decrypt-button,
and webmail-delete behavior still need the planned live-relay check when that environment exists.
