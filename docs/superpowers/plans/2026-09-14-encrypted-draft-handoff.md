# Encrypted Draft Handoff Implementation Plan

> **For agentic workers:** Execute one task at a time and keep the tests named below green. Do not alter the server wire contract.

**Goal:** Hand an Android composition to webmail without uploading plaintext when the account uses client custody, while keeping the composition available in Android whenever saving or opening webmail fails.

**Status:** Implemented on `feat/encrypted-draft-handoff` after parity PR #109 merged. Automated verification is recorded in [the implementation record](../handoffs/2026-09-14-encrypted-draft-handoff.md). Live relay/account checks below remain unrun.

**Architecture:** Add one encrypted-draft path alongside the existing no-upload handoff. The low-level `MailSource.saveDraft` transport still exists, but its unused `MailRepository` wrapper has been removed. On an enrolled client-custody device, build one complete PGP/MIME draft, encrypt and sign it to the public key derived from the locally unsealed private key, and post only `{to, pgpDraft}` to `/api/mail/draft`. On an unenrolled device there is no trusted key with which Android can encrypt: open webmail without saving, leave `ComposeActivity` alive, and keep its in-memory draft. Unknown custody also fails closed and never calls the plaintext draft path.

**Server contract:** `kypost-server` PR #185 is merged. `decodeMailRequest` accepts `pgpDraft`; `serveDraftSave` validates and appends that complete PGP/MIME value verbatim, ignores plaintext fields when it is present, and rejects plaintext drafts for client custody with `409 clientSideNeeded`. The request field is `pgpDraft`; there is no `kypostEncryptedDraft` flag. The encrypted payload must contain the real To/Cc/Bcc/Subject values as protected headers. The outer message keeps the required From, To, placeholder Subject, Date, MIME-Version, and `multipart/encrypted` Content-Type; it must not expose Cc or Bcc.

**Security boundary:** Never encrypt a draft to `PgpBootstrapResult.publicKey` or another relay-supplied key. Derive the public key from the private key released by `EnrollmentSession`, as `ClientEncryptedSender` already does for its Sent copy. Never fall back from an encrypted save to the plaintext `MailSource.saveDraft` transport. No-key and unknown-state handoffs transfer no compose fields or attachments to the relay or browser.

## Task 1: Express the exact encrypted-draft wire request

**Files:**
- Modify `app/src/main/java/org/kysecurity/mail/mail/MailSource.kt`
- Modify `app/src/main/java/org/kysecurity/mail/mail/RelayModels.kt`
- Modify `app/src/main/java/org/kysecurity/mail/mail/RelayMailSource.kt`
- Modify `app/src/main/java/org/kysecurity/mail/mail/MailRepository.kt`
- Test `app/src/test/java/org/kysecurity/mail/mail/RelayMailSourceTest.kt`

- [x] Add a redacted `ClientEncryptedDraft(to: String, pgpDraft: String)` domain value and `saveClientEncryptedDraft` to `MailSource` and `MailRepository`.
- [x] Add a dedicated serializable DTO containing exactly `to` and `pgpDraft`. Do not reuse `RelayMailRequestDto`: its subject, body, Cc, Bcc, mode, and attachments fields create opportunities to leak protected values beside the ciphertext.
- [x] Implement `RelayMailSource.saveClientEncryptedDraft` against the existing authenticated `/api/mail/draft` request/response machinery.
- [x] Test the URL and decoded JSON keys and values. Assert the request has `to` and `pgpDraft` and has no `body`, real `subject`, `cc`, `bcc`, or `attachments` key.

Run:

```bash
./gradlew :app:testPlayDebugUnitTest --tests "org.kysecurity.mail.mail.RelayMailSourceTest"
```

Expected: PASS.

## Task 2: Build one self-encrypted draft from existing crypto pieces

**Files:**
- Modify `app/src/main/java/org/kysecurity/mail/pgp/PgpMimeWriter.kt`
- Add `app/src/main/java/org/kysecurity/mail/pgp/ClientEncryptedDraftSaver.kt`
- Test `app/src/test/java/org/kysecurity/mail/pgp/PgpMimeWriterTest.kt`
- Add `app/src/test/java/org/kysecurity/mail/pgp/ClientEncryptedDraftSaverTest.kt`

- [x] Extend `buildProtectedContent` with optional To/Cc/Bcc protected-header inputs. Sanitize them with the existing header sanitizer and put them in the protected `text/rfc822-headers` part with Subject. Keep existing send callers source-compatible by defaulting the new inputs to empty lists.
- [x] Add a small `ClientEncryptedDraftSaver` orchestrator with the same `VaultOpener` pattern as `ClientEncryptedSender` and an injected encrypted-draft transport. Its outcomes must distinguish saved, cancelled, not enrolled/no key, no account address, encryption failure, and transport failure.
- [x] Build protected content from the exact `MailDraft`, including body and attachments. Parse and normalize recipients with the existing `splitRecipientFields`; require at least one To because the server decoder requires it. Put To/Cc/Bcc only inside the ciphertext, apart from the outer To required by the PGP/MIME envelope.
- [x] Open the local vault when needed. Inside `EnrollmentSession.withKey`, derive the own public key with `PgpEncryptor.ownPublicKey(privateKey)`, then call `PgpEncryptor.encrypt(protectedBytes, listOf(ownPublicKey), privateKey)` so the draft is both self-encrypted and signed. Wrap it with existing `wrapAsPgpMime`, using account address, To, date, placeholder Subject, and no outer Cc/Bcc.
- [x] Send the resulting `ClientEncryptedDraft` through the injected transport. Do not resolve recipient keys: drafts are encrypted only to the author and recipient discovery has no role here.
- [x] Test by decrypting the generated `pgpDraft` with the fixture private key and asserting protected To/Cc/Bcc/Subject, body, and attachment survive. Also test cancellation, missing enrollment/session, blank account address, encryption failure, and transport failure; assert transport is never called for every pre-encryption failure.

Run:

```bash
./gradlew :app:testPlayDebugUnitTest --tests "org.kysecurity.mail.pgp.PgpMimeWriterTest" --tests "org.kysecurity.mail.pgp.ClientEncryptedDraftSaverTest"
```

Expected: PASS.

## Task 3: Route handoff by verified custody and key availability

**Files:**
- Modify `app/src/main/java/org/kysecurity/mail/ComposePgpController.kt`
- Modify `app/src/main/java/org/kysecurity/mail/ComposeActivity.kt`
- Modify `app/src/main/res/values/strings.xml`
- Test `app/src/test/java/org/kysecurity/mail/ComposePgpControllerTest.kt`
- Add focused JVM tests for the handoff decision as a pure function in the nearest existing compose-state test file

- [x] Expose a pure handoff decision from the already fetched bootstrap state: `ENCRYPT_AND_SAVE` only for client custody plus a locally enrolled device plus a nonblank account address; `OPEN_WEBMAIL_WITHOUT_SAVE` for known client custody without a local key; `REFUSE_SAVE` for server custody and unknown/unrecognized state. Server-custody compose already has its native send and pickup-consent flows, so it has no reason to enter this webmail handoff. Keep this decision separate from UI text and network work.
- [x] In `ComposeActivity`, snapshot/export the draft once, resolve the webmail URL first, then execute the decision. For `ENCRYPT_AND_SAVE`, construct `ClientEncryptedDraftSaver` with `AndroidVaultOpener`, the controller's account address, and `repository.saveClientEncryptedDraft`; open webmail and finish only after the encrypted save succeeds.
- [x] Keep the existing no-transfer consent and composer retention for `OPEN_WEBMAIL_WITHOUT_SAVE`. On acceptance call `openWebmail` directly, without a draft request or finishing `ComposeActivity`; the existing `onStop`/`ComposeDraftCache` path retains the composition when returning from the browser.
- [x] For `REFUSE_SAVE`, show a retryable error and keep the composer. Do not guess custody and do not offer a plaintext consent path.
- [x] Preserve the parity branch's removal of plaintext-upload consent and its unused repository wrapper. The added encrypted branch must not restore a plaintext handoff.
- [x] On vault cancellation, unseal/encryption failure, transport failure, or missing browser handler, re-enable the chip and leave the fields, editor HTML, attachment objects, and Activity intact. Never clear `ComposeDraftCache` on these paths.
- [x] Extend the existing no-upload regression with recording fakes: client custody and unknown custody never call the plaintext transport, and no-key handoff calls neither draft transport.

Run:

```bash
./gradlew :app:testPlayDebugUnitTest --tests "org.kysecurity.mail.ComposePgpControllerTest" --tests "org.kysecurity.mail.pgp.PgpComposeStateTest" --tests "org.kysecurity.mail.ComposeDraftCacheTest"
```

Expected: PASS. If the pure-decision tests live under a differently named existing class, substitute that exact class.

## Task 4: Update contracts and verify the complete change

**Files:**
- Modify `app/src/main/AGENTS.md`

- [x] Run the DOX pass. Document that client-custody draft handoff is self-encrypted only on an enrolled device; unenrolled devices open webmail without transferring the composition; unknown custody never uploads plaintext.
- [x] Run the original Task 5 regression gate and all new focused tests:

```bash
./gradlew :app:testPlayDebugUnitTest \
  --tests "org.kysecurity.mail.EmailDetailActivityTest" \
  --tests "org.kysecurity.mail.ComposePgpControllerTest" \
  --tests "org.kysecurity.mail.mail.RelayMailSourceTest" \
  --tests "org.kysecurity.mail.pgp.PgpMimeWriterTest" \
  --tests "org.kysecurity.mail.pgp.ClientEncryptedDraftSaverTest" \
  --tests "org.kysecurity.mail.ComposeDraftCacheTest"
```

Expected: PASS.

- [ ] On a relay containing PR #185, manually verify an enrolled client-custody account: compose with To/Cc/Bcc, subject, body, and an attachment; hand off; confirm the Drafts row has the placeholder outer subject; open it in Android and confirm it offers Decrypt; decrypt and confirm every protected field and attachment. Confirm relay logs and IMAP contain no plaintext subject/body/Cc/Bcc.
- [ ] Manually verify an unenrolled client-custody device: enter the same fields, choose webmail, and confirm no `/api/mail/draft` request occurs, webmail opens without a transferred draft, and returning to Android retains the composition.
- [ ] Manually force a save failure and a missing browser handler; confirm the composer remains editable with all attachments present and retry enabled.

## Explicit non-scope

- Do not add an enrollment ceremony, copy a private key to an unenrolled device, or treat webmail handoff as enrollment.
- Do not trust the relay's bootstrap public key for self-encryption and do not add TOFU for the account's own key in this task.
- Do not invent wire fields, flags, delete APIs, draft IDs, or browser deep-link parameters for compose content.
- Do not add recipient discovery, pickup fallback, multi-device encryption, autosave, local disk persistence, or editable encrypted drafts to Android.
- Do not change the server repository in this implementation.
