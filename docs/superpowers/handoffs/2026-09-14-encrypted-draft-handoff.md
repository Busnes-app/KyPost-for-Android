# Encrypted draft handoff implementation record

**Repo:** kypost-android
**Branch:** feat/encrypted-draft-handoff

Continues merged PR #109 from main `1548c04`. The [saved plan](../plans/2026-09-14-encrypted-draft-handoff.md) is implemented without server changes or new dependencies.

An enrolled client-custody device offers to save a self-encrypted draft before opening webmail. The saver derives the public key from the locally unsealed private key, signs and encrypts the complete MIME content, and uploads exactly `{to, pgpDraft}`. To/Cc/Bcc/Subject and attachments are protected inside the ciphertext; only the required outer To and placeholder Subject remain outside it. Recipient discovery and bootstrap public keys are not involved. The temporary plaintext byte buffer is wiped after encryption.

Unknown custody refuses the operation. Unenrolled client-custody devices keep the existing consented no-transfer handoff. An in-flight modal prevents edits while saving; cancellation, failed unlock/encryption/save, and failed browser launch retain the composition. Even a successful save and browser launch leaves the composition available in Android. Enrollment is re-probed after consent, stale editor callbacks cannot start a later attempt, and Activity destruction cancels its pending vault prompt.

## Verification

The exact wire-shape test, signed self-decrypt roundtrip, recipient-header sanitization, custody matrix, enrollment re-probe, failed/lost unlock, bad key, transport failure and cancellation tests cover the security boundary. The full API 36 suite completed 242 cases with zero failures/errors and four existing device-precondition skips. The new device tests exercise the real browser/cache behavior for failure and browser-launch outcomes; strengthened retention checks also cover all restored fields and attachments.

Before the review corrections, all local gates passed in 4m43s: 1,196 JVM cases per Play/GitHub/F-Droid flavor, zero failures/errors/skips; all three lint, release APK, runtime class-name and exported-component checks; and the signing-secret gate. The final strengthened handoff/compose-retention device subset passed all three cases. Verification logs cover the combined Gradle gates and the full device suite. PR CI and independent security review follow the push.

## Limits

No paired live relay/account was available, so live webmail decryption, IMAP inspection and real browser/PWA handoff remain unverified. Server request decoding and draft validation were checked against the local server source; the server repository was not modified.

The API exposes no draft identity/upsert. Retrying after a save succeeded but browser launch failed, or after a cancelled in-flight request whose server outcome is unknown, may create another encrypted draft. The Android composition remains available. There is no autosave, disk persistence, enrollment, recipient fallback, or editable encrypted-draft feature added here.

Existing outgoing attachment limits and encryption memory behavior remain; this change does not claim a new whole-process heap guarantee. Existing API31 pre-attachment SystemUI cancellation behavior remains as documented by parity PR #109. Release verification uses a disposable signing key, not a production release identity.

## Independent review corrections

The draft transport now requires a JSON boolean `ok:true`; malformed or negative 200 responses fail. This still cannot distinguish an older relay that ignores `pgpDraft`, so successful handoff also retains the local composition through the normal `onStop` cache path. The user decides when to discard it. This conservative preservation rule supersedes the original plan's finish-after-success step. The server source supports the encrypted request, but live storage/readback remains unverified.

Consent now states that content, Cc/Bcc and attachments are encrypted while From/To/date metadata is visible to the server. The new public record uses repository/branch references instead of local host paths. Before-fix tests failed on both unacknowledged-200 admission and successful-handoff discard; the fixes preserve a recoverable composition.

After the review corrections, 60 focused JVM tests, both handoff device tests and Play lint passed. The full Play JVM suite passed 1,197 cases with zero failures/errors/skips before the fix push. The current CI matrix and independent re-review remain the final PR gates.
