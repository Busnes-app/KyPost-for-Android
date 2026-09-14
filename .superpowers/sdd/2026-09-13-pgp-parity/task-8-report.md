# Task 8 report: bounded secret-key rotation merge

**Repo:** kypost-android
**Worktree:** /home/yoshi/busness.app/kypost-android/.claude/worktrees/pgp-parity (branch worktree-pgp-parity)

## Outcome

- Added `mergeSecretKeyRings(current, previous)`, returning armored bytes with every current ring
  first and each absent historical primary appended.
- When current and historical material share a primary fingerprint, the merge restores every
  historical secret subkey missing from the current ring. It verifies retention before serializing.
- Invalid or empty material, non-ASCII historical armor, an input/output cap breach, an excessive
  ring count, or any parse/serialization failure returns null. No partial or current-only result is
  produced.
- The bounded output stream wipes every replaced, copied, or abandoned backing buffer and exposes
  only a redacted `toString`. Production never converts private-key material to `String`.

## Bounds and memory

- New/current key input: 256 KiB.
- Previous merged vault input: 384 KiB, equal to the maximum accepted output so a successful vault
  remains admissible at the next enrollment.
- Merged armored output: 384 KiB.
- Primary rings: 32.
- Separately accounted enrollment peak: 3,276,800 bytes (about 3.1 MiB), independently asserted
  below the 128 MiB assumed heap. The existing reader peak is unchanged.

These are refusal limits. The merge never truncates or drops a historical key to fit them. The
upgrade path for unusually large collections is a streaming parser/serializer.

## Bouncy Castle order finding

The first deliberate reverse-order mutation unexpectedly stayed green. Inspection of bcpg 1.79
found that `PGPSecretKeyRingCollection` records encoded order but `getKeyRings()` iterates
`secretRings.values()` from a map. Consequently the old `PgpEncryptor` signer and own-public-key
selection used hash-map order rather than packet order.

Task 8 therefore adds one strict `PGPObjectFactory` helper that preserves encoded packet order and
rejects unexpected content. The merge parser, signing-key selection, and own-public-key derivation
all reuse it. Decryption remains unchanged because it selects by recipient key ID across the whole
collection.

## Verification

- Focused PlayDebug suite:

  `./gradlew :app:testPlayDebugUnitTest --tests "org.kysecurity.mail.pgp.SecretKeyRingMergeTest" --tests "org.kysecurity.mail.MemoryBudgetTest" --tests "org.kysecurity.mail.pgp.PgpEncryptorTest"`

  **PASS** after restoring the deliberate mutation.
- Coverage includes current-first raw order, idempotent re-enrollment, old-key decryption, new-key
  signing, current own-public-key derivation, same-primary historical subkey retention, invalid and
  empty collections, both input caps, non-ASCII historical input, ring count, output cap, and the
  enrollment memory sum.
- Deliberate break: inserted an absent historical ring at index zero. With the strict ordered parser,
  the raw-order, new-key-signing, and current-own-public-key tests all failed. Restored current-first
  append and reran green.
- `git diff --check`: **PASS**.

## DOX

Updated `app/src/main/AGENTS.md` with fail-closed rotation, historical subkey retention, the memory
limits, and the requirement to use ordered secret-ring parsing for order-sensitive consumers.

## Concerns

No functional blocker remains. The 32-ring/384-KiB limits intentionally refuse pathological account
histories; raising them requires revisiting the enrollment peak and streaming upgrade described in
`MemoryBudget`.
