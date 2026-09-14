# Encrypted draft handoff implementation record

**Repo:** kypost-android
**Worktree:** /home/yoshi/busness.app/kypost-android/.claude/worktrees/encrypted-draft (branch feat/encrypted-draft-handoff)

Continues merged PR #109 from main `1548c04`. The [saved plan](../plans/2026-09-14-encrypted-draft-handoff.md) is implemented without server changes or new dependencies.

An enrolled client-custody device offers to save a self-encrypted draft before opening webmail. The saver derives the public key from the locally unsealed private key, signs and encrypts the complete MIME content, and uploads exactly `{to, pgpDraft}`. To/Cc/Bcc/Subject and attachments are protected inside the ciphertext; only the required outer To and placeholder Subject remain outside it. Recipient discovery and bootstrap public keys are not involved. The temporary plaintext byte buffer is wiped after encryption.

Unknown custody refuses the operation. Unenrolled client-custody devices keep the existing consented no-transfer handoff. An in-flight modal prevents edits while saving; cancellation, failed unlock/encryption/save, and failed browser launch retain the composition. Only save plus successful browser launch clears the cache and finishes. Enrollment is re-probed after consent, stale editor callbacks cannot start a later attempt, and Activity destruction cancels its pending vault prompt.

## Verification

The exact wire-shape test, signed self-decrypt roundtrip, recipient-header sanitization, custody matrix, enrollment re-probe, failed/lost unlock, bad key, transport failure and cancellation tests cover the security boundary. The full API 36 suite completed 242 cases with zero failures/errors and four existing device-precondition skips. The new device tests exercise the real finish/cache behavior for failure and browser-launch outcomes; strengthened retention checks also cover all restored fields and attachments.

Final local gates passed in 4m43s: 1,196 JVM cases per Play/GitHub/F-Droid flavor, zero failures/errors/skips; all three lint, release APK, runtime class-name and exported-component checks; and the signing-secret gate. The final strengthened handoff/compose-retention device subset passed all three cases. Logs: `/tmp/kypost-encrypted-draft-final-checks.log` and `/tmp/kypost-encrypted-draft-device.log`. PR CI and independent security review follow the push.

## Limits

No paired live relay/account was available, so live webmail decryption, IMAP inspection and real browser/PWA handoff remain unverified. Server request decoding and draft validation were checked against the local server source; the server repository was not modified.

The API exposes no draft identity/upsert. Retrying after a save succeeded but browser launch failed, or after a cancelled in-flight request whose server outcome is unknown, may create another encrypted draft. The Android composition remains available. There is no autosave, disk persistence, enrollment, recipient fallback, or editable encrypted-draft feature added here.

Existing outgoing attachment limits and encryption memory behavior remain; this change does not claim a new whole-process heap guarantee. Existing API31 pre-attachment SystemUI cancellation behavior remains as documented by parity PR #109. Release verification uses a disposable signing key, not a production release identity.
