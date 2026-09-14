# Task 5 current compatibility report

## Outcome

- The client-custody webmail handoff no longer exports the editor, snapshots a `MailDraft`, or
  calls the plaintext `/api/mail/draft` path.
- The confirmation now says that the composition will not be transferred and that the current
  fields and attachments remain in Android.
- Accepting opens the existing first-party Drafts URL without recipients, subject, body, or
  attachment data in the URL or Intent. `ComposeActivity` is not finished, so its existing
  `onStop` path retains the live composition in `ComposeDraftCache` for return from the browser.
- Cancel, target-resolution failure, and browser-launch failure leave the composer editable and
  re-enable the handoff chip through the existing dialog-dismiss or failure paths.
- Removed the now-unused `MailRepository.saveDraft` wrapper and stale plaintext-save failure copy.
  The lower-level `MailSource.saveDraft` remains for the relay wire contract and its existing test.
- Updated the nearest production DOX contract with the no-transfer and lifetime rules.

## Verification

- Focused JVM gate:

  `./gradlew :app:testPlayDebugUnitTest --tests 'org.kysecurity.mail.SourceRulesTest' --tests 'org.kysecurity.mail.pgp.WebmailDeepLinkTest' --tests 'org.kysecurity.mail.ComposeDraftCacheTest' --tests 'org.kysecurity.mail.ComposePgpControllerTest'`

  **PASS, 43 tests.** `WebmailDeepLinkTest` proves the handoff URL contains only the Drafts mailbox
  selector. `SourceRulesTest` proves the handoff region cannot export or construct a composition,
  call `saveDraft`, clear `ComposeDraftCache`, or finish the activity. The existing cache and
  controller tests cover draft lifetime and the no-key/409 entry state.

- Deliberate break: temporarily restored `finish()` after a successful browser launch. The focused
  source-boundary test failed with `finish()` as the offender. Restored the intended implementation
  and reran the full focused gate successfully.
- `./gradlew :app:lintPlayDebug`: **BUILD SUCCESSFUL**.
- `./gradlew :app:connectedFdroidDebugAndroidTest -Pandroid.testInstrumentationRunnerArguments.class=org.kysecurity.mail.ui.ComposeDraftSurvivesTeardownTest`:
  **PASS, 1 test** on the API 36 `kypost_parity_validation` emulator. This exercises the real
  Activity teardown/recreation path and proves its fields, body mirror, and attachment survive via
  `ComposeDraftCache`.
- `git diff --check`: **PASS**.
- The first focused run failed because the new source test looked for `ComposeActivity.kt` as a
  root-relative filename while the helper records its package-relative path. The lookup was fixed
  to match the suffix before the deliberate break and final green run.

## Limits and concerns

- No live browser-return UI check is claimed. Browser availability remains isolated behind the
  previously tested `openWebmail` launcher; the focused device check covers the Activity/cache
  lifetime that browser launch triggers.
- The separate encrypted-draft follow-up plan remains untracked and unchanged at
  `docs/superpowers/plans/2026-09-14-encrypted-draft-handoff.md`; this compatibility commit does not
  implement it.
