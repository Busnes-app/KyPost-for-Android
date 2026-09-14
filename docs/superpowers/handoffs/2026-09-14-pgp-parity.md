# Android PGP parity implementation record

**Repo:** kypost-android

**Branch:** worktree-pgp-parity

**Worktree:** /home/yoshi/busness.app/kypost-android/.claude/worktrees/pgp-parity

**Plan:** [2026-09-13-pgp-parity.md](../plans/2026-09-13-pgp-parity.md)

## Delivered behavior

- Decrypted MIME attachments stay in memory and can be opened through the existing ephemeral content provider or explicitly saved through the existing download sink. Raster CID images render through the sanitized encrypted-message path. CID expansion is capped at 128 KiB, and the sanitizer shares that allowance across literal and rewritten data-image URLs in both image-display variants. Decrypted bytes never enter Room, cached fetched HTML, or the attachments used by Forward.
- Attachment retention is capped at 4 MiB total, with one owned save snapshot. Completed read results retain a cleanup owner across dispatcher delivery and rendering; cancellation or rejection wipes arrays before UI adoption. Queued snapshots are wiped on teardown; an already-started save finishes with its own stable bytes and then wipes them. The modeled read allocation peak, including decoding growth, save/open copies, and conservative added-image render scratch, is 123.5 MiB against a 128 MiB assumption. This models buffers, not a measured whole-process peak or a bound on arbitrary original HTML, general DOM overhead, or WebView image decoding.
- Successfully decrypted unsigned messages say “Encrypted, not signed,” including messages without a resolved sender. Existing signed-only verification behavior remains.
- Re-enrollment preserves retired keys and missing historical subkeys, retains nonempty historical private packets for a matching fingerprint, and keeps current public metadata and packet order for signing and own-key selection. Storage errors and incomplete/corrupt records are distinct from confirmed absence. Failed unlocks or refused merges leave the stored vault unchanged; only genuine first enrollment can seal current-only material.
- Merge limits are 256 KiB current input, 384 KiB previous input/output, and 32 rings. Invalid, incomplete, or excessive key material is refused. Merging does not execute incoming password-derivation parameters. The separately modeled enrollment buffer peak is 3,940,352 bytes; it does not claim to measure Bouncy Castle's object heap.
- Destroying the enrollment Activity resolves its pending old-vault prompt as cancelled, including during rotation. Stale callbacks cannot repopulate the key session.
- Webmail handoff explains that it transfers no composition, makes no draft request, and leaves the Android composer available. Server PR #185 rejects client-custody plaintext draft uploads. Full self-encrypted draft saving is **not implemented here**; it has a [separate follow-up plan](../plans/2026-09-14-encrypted-draft-handoff.md).
- Regression coverage pins encrypted bodyless delta rows and tolerance of unknown resolver tiers and signer sources.

## Verification

Verified implementation: `7719c71` (subsequent documentation changes do not change runtime code). Whole-branch review and scoped follow-ups approved; all reported blockers are closed.

| Check | Play | GitHub | F-Droid |
| --- | --- | --- | --- |
| JVM unit suite | 1,185 passed | 1,185 passed | 1,185 passed |
| Lint | 0 errors, 284 warnings | 0 errors, 294 warnings | 0 errors, 294 warnings |
| Release APK assembly, disposable verification signer | Passed | Passed | Passed |
| Runtime matched class-name gate | Passed | Passed | Passed |
| Exported-component gate | Passed | Passed | Passed |

All unit suites had zero failures, errors, or skipped tests. The signing-secret check and `git diff --check` also passed. The final combined Gradle invocation completed in 4m. Reproduce its gates with:

```bash
./gradlew checkSigningSecretsAreNotInTheTree \
  checkExportedComponentsPlayDebug checkExportedComponentsGithubDebug checkExportedComponentsFdroidDebug \
  :app:testPlayDebugUnitTest :app:testGithubDebugUnitTest :app:testFdroidDebugUnitTest \
  :app:lintPlayDebug :app:lintGithubDebug :app:lintFdroidDebug \
  :app:assembleRelease \
  :app:checkRuntimeMatchedClassNamesPlayRelease \
  :app:checkRuntimeMatchedClassNamesGithubRelease \
  :app:checkRuntimeMatchedClassNamesFdroidRelease
```

Release packaging needs the disposable key supplied through `KYPOST_*` environment variables, as in CI. Production signing credentials are not needed for this verification.

Focused checks completed during implementation include MIME/CID parsing, attachment ownership and filename handling, unsigned display, delta sync, real retired-key decryption/current-key signing, invalid and over-limit merge refusal, and enrollment buffer/session cleanup. Deliberate mutations were used to prove the affected regression assertions.

The final PlayDebug device runs passed all **42 tests** on the disposable API 36 emulator: the full PGP package (29) plus attachment/provider/composer checks (13).

```bash
ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedPlayDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.package=org.kysecurity.mail.pgp
ANDROID_SERIAL=emulator-5554 ./gradlew :app:connectedPlayDebugAndroidTest \
  -Pandroid.testInstrumentationRunnerArguments.class=org.kysecurity.mail.security.AttachmentDownloadCleanupTest,org.kysecurity.mail.security.EphemeralAttachmentProviderTest,org.kysecurity.mail.ui.ComposeDraftSurvivesTeardownTest
```

Coverage includes the existing enrollment/vault/teardown/worker checks, storage failure and corruption, actual renderer adoption/rejection and destruction, attachment downloads and ephemeral-provider cleanup, and composer retention. DeviceEnrollmentOpenLifecycleTest waits for an actual pending biometric prompt: removing destroy cancellation made it fail after five seconds with a stranded-open assertion; restoring cancellation passed.

The old pre-existing emulator was credential-locked and could not access shared storage. Those attachment setup failures were reproduced and resolved by using a new unlocked disposable AVD; the original AVD was not wiped.

## Final review corrections

The whole-branch review identified two historical-key preservation failures and a cancelled-result cleanup gap. The fixes distinguish unavailable storage from an absent vault, retain historical private packets with current public metadata, and keep attachment cleanup ownership until the UI accepts the result. All three failures were deliberately restored: storage classification, historical decrypt, and queued-delivery cleanup regressions failed; restoring the fixes returned them to green.

The first key-usability fix exposed an allocation risk by executing incoming Argon2 parameters. That extraction was removed entirely. A committed regression traps any merge-time private extraction, and the reviewer's real 816-byte input subsequently merged under a 64 MiB JVM heap without the earlier out-of-memory condition. Bounds stay unchanged.

## Not run / follow-up

- No paired live relay/account was available for the encrypted-message attachment/CID roundtrip, Proton interoperability, changed-relay delta run, or full device key-retirement/re-enrollment roundtrip.
- No production signing identity is available in this session. Local release packaging uses a disposable verification identity, matching CI's approach; these APKs are not production releases.
- Implement the separate encrypted-draft plan before claiming encrypted draft-save parity.

## Decisions made during execution

The original plan below remains a historical implementation recipe. The following ledger rulings record deviations and their reasons; later rulings supersede earlier ones where stated. In particular PlayDebug became available, attachment retention was lowered, and the server draft decision was resolved.

- Ruling: a `message/rfc822` leaf inside the ciphertext is collected as an attachment (bytes of the nested message) rather than walked — the old walk dropped it; a file is strictly better and YAGNI on nested rendering. Costs if wrong: a forwarded-as-attachment message shows as a `.eml` chip instead of inline text.

- Ruling: tests run on the fdroid flavor because the worktree command guard refuses the github flavor's task name and play needs a secret file. Costs if wrong: a flavor-specific source set difference goes untested here; PR CI covers all flavors.

- Ruling: dropped the unused `count` parameter from `decryptedAttachmentNotice` (YAGNI). Costs if wrong: nothing downstream used it.

- Ruling: text/html and text/plain leaves are body candidates unless Content-Disposition is `attachment`; a name= parameter or a Content-ID on a text part does not make it a file (multipart/related mailers stamp Content-ID on the HTML body; Outlook-lineage senders put name= on body text). Non-text, non-multipart leaves stay attachments. Costs if wrong: an inline `.txt` attachment lacking a disposition is read as a body candidate and, when a body already exists, is dropped.

- Ruling: `blockExternalResources` keeps raster data: `img` sources only when a new parameter `keepInlineDataImages: Boolean = false` is true; `renderableBody` gains the same parameter and forwards it; Task 4 passes true only from the Decrypted branch. Plaintext mail keeps today's behaviour, the "Show images" consent gate is unchanged there, and the only kept data: bytes are the ones `INLINE_IMAGE_BYTES` already counts (sender-authored data: images inside a decrypted body sit in the plaintext term). Costs if wrong: a legitimate inline data: image in ordinary mail stays hidden, as it is today.

- Ruling: break-proof is required for the two tests whose assertions could survive a broken implementation (the inline budget test and the new srcset test); the remaining new tests assert a single direct property whose only break is deleting the feature, and the SVG break already covered two. Costs if wrong: a subtly weak assertion among those slips through to the final review.

- Ruling: rename `anUnparseableFragmentComesBackUntouched` to `anEmptyFragmentComesBackUntouched`; the jsoup-failure fallback stays untested because the sanitiser downstream is the control. Costs if wrong: none beyond an honest name.

- Ruling: Task 5 question is answered; do not post a stale question. Its encrypted-save follow-up requires a new focused plan as Task 5 explicitly says. Existing Android handoff is offered on unenrolled devices, which do not have the key required to encrypt; preserve the composer and never send plaintext to discover custody.

- Ruling: Task 7 fixture is changeType=new and its expected updatedMessageIds is empty; the comment saying it must be updated contradicts both. Keep the wire distinction, cover new and updated encrypted rows with accurate assertions.

- Ruling: Task 9 must fail closed on a failed previous-vault open or invalid new merge instead of overwriting a potentially recoverable vault. OpenOutcome.Failed does not prove permanent key invalidation. Cost: transient failures need retry; historical keys are preserved.

- Ruling: Task 8 merge must bound input/output and reject empty or invalid current rings; enrollment must distinguish merge failure from no previous key. The suggested unbounded serialization and nullable fallback violate preservation/allocation contracts.

- Ruling: Task 4 fixes may revise the plan's byte ceiling downward and account for both bounded attachment decoding growth and one in-flight save/open copy. Preserve 128 MiB heap assumption, prevent unbounded queued copies, zero owned save buffers on completion or scheduling failure, and pass raw filenames to the existing sanitizing sink.

- Task 6: implemented at 75904dc; 477 focused tests pass, unsigned mapping deliberate-break fails as expected. Review pending. Fixture ruling: ARMORED_MIME_MESSAGE is actually signed, so generate a genuinely unsigned encrypted payload for the new regression.

- Ruling Task5: implement current no-upload webmail fallback, preserving Android composer; full encrypted saver remains separately planned as original Task5 explicitly requires. Enrolled missing-recipient handoff exists but most handoffs lack private key; no ordinary save-draft UI exists. This closes now-rejected plaintext upload without adding an unreachable draft feature. Cost: webmail receives no composition until encrypted saver followup is implemented; UI must state this explicitly.

- Task8 additional ruling: invalid nonempty previous key material must fail merging, rather than silently drop a partially recoverable prior collection. Task9 treats that failure as preservation/retry, never fallback to sealing current-only. A first enrollment has no previous material and follows its separate branch. Add size/ring-count limits in MemoryBudget with a separately tested enrollment peak, since merge and mail-read are distinct operations; do not pretend every enrollment allocation is concurrent with reader allocations.

- Task8 library ruling: BC collection iteration is map order; include shared packet-order parsing in merge and PgpEncryptor own-key/sign selection. Original serialization-order assumption disproved by deliberate mutation. Also previous input cap must accept max successful merged output. Details task-8-rulings.md.

- Task9 UI ruling: cancellation may remain ReadyToFinish; failed vault open and malformed/over-limit merge should use honest generic failure (existing SEAL_FAILED) rather than Almost done/authentication-only copy, while never altering old vault. Agreement-key teardown on true failure is acceptable; user can restart ceremony.

- Ruling: final release packaging may use a disposable verification signing key, matching CI; production signing credentials are unavailable. Artifacts are verification-only and must not be published as a production release. Cost if wrong: no production-signature validation is claimed.

- Ruling: for a matching fingerprint, retain a nonempty historical private packet with the current public metadata, without running any incoming KDF during merge. The same fingerprint identifies the same key; history preservation does not require testing attacker-supplied password derivation. Cost: re-enrollment will not silently repair a corrupt nonempty historical packet for the same fingerprint; that requires explicit recovery rather than risking key loss or unbounded allocation.

- Ruling: apply one narrowly scoped follow-up for the new allocation blocker and re-review it, despite the skill's one-wave stopping guideline. This is an authorized reversible correctness fix, and handing off a known avoidable key-import OOM would leave the task unfinished. No broader second review/fix wave.

## PR instrumentation follow-up

PR #109's first CI matrix exposed a test-order failure reproduced locally: the new reader Activity fixture retained `MailRuntime` after scenario teardown, and subsequent database-wipe tests left that cached DAO closed. Commit `cf43e5a` releases the mail graph in fixture teardown and documents its ownership; production code is unchanged.

The ordered six-test reproduction now passes. Full Play and F-Droid instrumentation on API 36 each completed 240 cases with zero failures/errors and four existing device-precondition skips (one AuthGateKeyTest and three BiometricUnlockVaultTest cases). The initial F-Droid run hit a separate embedded-pane lock assertion; both its isolated retry and a full-suite retry passed without changes. That transient failure is recorded, not claimed fixed. Full CI across API 31/34/36 and independent review remain PR gates.

The next matrix passed unit, release, CodeQL, API 34 Play/F-Droid, and API 36 Play. API 31 completed its suite but two compose Espresso checks lost focus to a system BiometricPrompt left by the new rotation fixture. A local A/B reproduced this: compose alone passed; prompt lifecycle then compose failed. The fixture had checked request registration before the prompt window attached. Commit `d3b7084` waits for the visible prompt and additionally checks that the replacement Activity regains focus. Disabling actual prompt cancellation makes that new assertion fail. Restored full API 31 instrumentation passed 236 cases plus four assumption skips; five affected API 36 cases passed.

This fixture correction does not fix Android 12 SystemUI's observed pre-attachment cancellation race: a real extremely early Activity teardown can still encounter that platform behavior. App cancellation was delivered in the trace; no production timing workaround was added.

## Independent review follow-up

The PR reviewer identified a literal data-image budget bypass and an undercount of retained/transient HTML copies. Before-failing regressions confirmed both; an additional malformed-base64 case demonstrated attribute-escaping growth. The sanitizer now charges complete raster data URLs to an aggregate allowance, rejects non-base64 payload characters without decoding, and applies the same limit when remote images are enabled. Existing plaintext behavior is unchanged.

The inline allowance is reduced from 3 MiB to 128 KiB; larger CID parts remain available as attachments within the 4 MiB attachment limit. The model conservatively reserves twelve base64/UTF-16-sized copies (36 times the inline allowance) for retained variants and rendering scratch. Its total is 129,499,136 bytes (123.5 MiB), and a regression requires at least 4 MiB of headroom. This does not claim a general browser/HTML heap ceiling.

Final local gates after `7719c71`: all three complete JVM suites (1,185 cases each, zero failures/errors/skips), all three lint/release/runtime-name/exported-component gates, and the signing-secret check passed. CI and independent exact-head re-review follow the final push.
