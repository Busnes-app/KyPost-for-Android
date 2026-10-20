# Handoff — "GPG messages won't open on Android", and the two mailboxes it cost

**Status:** CLOSED. Root cause found and fixed, verified on device. See §0.
**Date:** 2026-08-24
**Owner:** unassigned
**Repos touched:** `kypost-server`, `kypost-android`. Findings only for `kypost-for-Mac`, `kypost-Linux`.
**Shipped:** [Android#82](https://github.com/Busnes-app/KyPost-for-Android/pull/82),
[Android#83](https://github.com/Busnes-app/KyPost-for-Android/pull/83),
[Android#84](https://github.com/Busnes-app/KyPost-for-Android/pull/84),
[Server#134](https://github.com/Busnes-app/KyPost-Server/pull/134)

> **Two retractions live in this document. Read §0 first.** §3's "R8 is exonerated" was wrong, and
> §3.1's replacement candidate was also wrong. Both are kept, struck through rather than deleted,
> because the shape of the error is the most reusable thing here: inference recorded as proof, twice,
> about the same subsystem.

---

## 0. Root cause — R8 removed the MIME content handlers

`META-INF/mailcap` binds five jakarta.mail content handlers by fully-qualified **string**, and
`MailcapCommandMap` loads them by name. No bytecode refers to them, so R8 deleted all five: an
actual release `mapping.txt` carried 128 `angus` lines and **zero** `angus.mail.handlers`.

jakarta.activation then falls back to `DataSourceDataContentHandler`, whose `getContent()` answers
an `InputStream` rather than a `String` or a `MimeMultipart`. In `PgpMimeReader` that makes
`content as? String` null and `content is MimeMultipart` false, so both the html and plain parts
stay null, `read()` returns null, and the reader reports
`DecryptFailed("this message could not be read once decrypted")`.

**Decryption always worked.** Parsing the decrypted plaintext is what failed — every encrypted
message, every release build, since the handlers were first shrunk away.

Fixed in `938f5c7` with five explicit `-keep` rules. Not a wildcard: `handlers.**` also keeps
`image_gif` and `image_jpeg`, which reference `java.awt.Image` and `java.awt.Toolkit` and fail the
R8 step outright on Android, and mailcap declares neither.

**Verified on device**, 2026-08-24: a release build from `fix/mailcap-content-handlers` reads
encrypted mail. That is the end of this incident.

### 0.1 How it stayed hidden, which is the part worth keeping

- **The user-visible symptom was a wordless padlock.** Every one of eight outcomes rendered the
  same. Naming them (`7eae633`) is what turned this from a guessing game into a diagnosis: the
  release build said *"could not be read once decrypted"* and that sentence is one line of code.
- **No unit test could see it.** The suite runs unminified with every handler on the classpath. A
  green thousand-test suite sat on top of a broken release for two versions.
- **`missing_rules.txt` was empty and stayed empty.** R8 has no complaint about deleting a class
  nothing references. Its silence was read as evidence twice (§3, §3.1) and it never was any.
- **The check that works reads `mapping.txt`.** `checkRuntimeMatchedClassNames`
  (`app/build.gradle.kts`) fails the build when a name in `runtimeMatchedClassNames` is renamed or
  shrunk away. Built for §3.1's defect, it caught this one red on all five handlers.
- **The reproduction that cracked it was the user's, not the investigation's:** same source, wipe in
  between, release fails and debug succeeds. One sentence, and it falsified a "settled" fact.

---

---

## 1. What happened

Reported as "something broke reading GPG messages on mobile devices". Worked on Linux, failed on
Android and Mac. Pressing Decrypt, unlocking, and getting a padlock plus an Open-in-webmail button.

The causal chain, in order:

1. ~~**PGP enrollment never completed on the device.**~~ **Wrong — see §0.** Enrollment was fine.
   R8 had removed the MIME content handlers, so every decrypted message failed to parse. Steps 2
   and 3 below describe what the app *showed*, which is why this was misread for so long; step 1
   is the reading, not the fact. Kept because steps 4 and 5 follow from the misreading and did
   real damage.
2. `VaultOpenerAndroid.kt:36` — `vault.stored() ?: return NotEnrolled`. This runs **before** any
   biometric prompt, so the "unlock" the user performed was the *app lock*, not the vault. The
   reader correctly returned `ReadOutcome.NotEnrolled`.
3. `EmailDetailActivity.renderReadOutcome` passed `""` to `showLocked`, collapsing eight outcomes
   into one wordless padlock. Six strings were authored for exactly these rows and had **zero**
   references in code — including the accurate one: *"this device holds no key. Enrol this device
   in Security settings."*
4. Seeing no explanation, the user concluded decryption was broken and reached for unpair/re-pair —
   which `MailSource.kt:57` explicitly recommended for a changed certificate.
5. On a build predating `ad4fd87`, `attemptPairing` purged the account **before** the network call.
   The purge succeeded, the call failed, the mailbox was gone. **This happened twice.**

Recovery was: reinstall, redo enrollment, decrypt works. Nothing about the decrypt code changed —
and in hindsight nothing about the *enrollment* mattered either. What changed was the build: the
reinstall was a debug build, which carries the content handlers §0 shows R8 strips from release.
Re-enrolling got the credit for a fix that came from not minifying. That false confirmation is what
made "redo the enrollment" look like a working remedy, and it is why it was reached for twice.

## 2. What shipped

| Commit | Repo | What |
|---|---|---|
| `7eae633` | android | `readFailureNotice(outcome)` — each failure gets its own sentence; `DecryptFailed`/`FetchFailed` carry their detail |
| `3b17dec` | android | `MailSource.kt:57` now points at **Reconnect to server**, not unpair/re-pair |
| `dc2fd00` | server | Enrollment hint `XXXXXXX-XXXXXXX` → `XXXX-XXX-XXXX-XXX` |
| `924a689` | android | `-keepnames` for Tink's shaded parse failure + `checkRuntimeMatchedClassNames` build gate — see §3.1 |
| `0ebc9ac` | android | Signed-only mail verified and rendered over `signedPartBase64`, never over `body` |
| `dc635bb` | android | An unparseable signed part stays readable, and renders as text not markup |
| `938f5c7` | android | **The fix.** Five `-keep` rules for the jakarta.mail content handlers — see §0 |

`e930a0d` is the pre-rebase hash of `924a689`; PR #83 rebased onto `main`.

Verified: `testDebugUnitTest` 1024 passed / 0 skipped / 0 failures, `lintDebug` clean,
`checkRuntimeMatchedClassNamesRelease` red before each of `924a689` and `938f5c7` and green after,
and a release build reading encrypted mail **on device**;
`deviceEnrollment.test.ts` 32 passed, `DeviceMailAccess.test.tsx` 25 passed, `tsc --noEmit` clean.

## 3. Established facts — do not re-derive these

Each cost real time. They are settled.

- **`app/src/main/java/org/kysecurity/mail/pgp/` is byte-identical between the last 0.3.2 commit
  (`383c043~1`) and HEAD.** `git diff 383c043~1..HEAD -- app/src/main/java/org/kysecurity/mail/pgp/`
  returns zero lines. The decrypt code never had a bug.
- **The `v0.3.3` tag points at HEAD (`3e121ac`).** The GitHub release and a local build have
  identical source; version was never the variable. Note it is an *annotated* tag, so
  `git rev-parse v0.3.3` returns the tag object (`2bdff00`) and looks like a mismatch. Use
  `git rev-parse 'v0.3.3^{commit}'`, which equals `main`, with
  `git log 'v0.3.3^{commit}'..main` empty.
- ~~**R8 is exonerated.**~~ **RETRACTED 2026-08-24 — this was wrong, and it was the costliest
  line in this document.** It was inference (an empty `missing_rules.txt`, one BouncyCastle
  constructor surviving `mapping.txt`) written down as proof, and it steered the investigation
  away from the one place that was actually broken. Yoshi then reproduced the opposite: same
  source, wipe in between, release fails to open the message and debug opens it. See §0.
  What *is* settled about R8, checked against `mapping.txt` rather than reasoned about:
  BouncyCastle decryption uses the lightweight `Bc*` operators (`PgpDecryptor.kt:98`), which are
  switch-dispatched and carry no `Class.forName`; and every `org.kysecurity.mail.**$$serializer`
  survives unrenamed, so R8 does not break the fetch/deserialize path.
- **Linux is not affected by the destructive-purge bug.** `PairingController.cpp:633` gates the
  purge on `RegistrationOutcome::Success` inside the network callback — verified in code, not just
  the comment above it.
- **Mac/iOS has no account-replacement purge at all**, so it cannot hit that bug either.
- **Linux and Mac/iOS both give every read failure its own sentence** —
  `PgpMessagePresentation.cpp:69` (`pgpReadFailureMessage`) and
  `EncryptedReadViewModel.swift:73` (`statusMessage`). The silent padlock was Android-only.
- **The enrollment-hint fix does not explain the failure.** Both sides strip separators before
  comparing (`deviceEnrollment.test.ts` covers it). A correctly typed code was never rejected for
  this. It is a clarity fix.

### 3.1 A proven release-only divergence — real, fixed, and ~~possibly~~ **NOT** the trigger

**Resolved 2026-08-24: this was not the cause. §0 is.** The defect below is real and worth having
fixed, and the build gate it produced is what later caught the actual bug — but naming it a likely
trigger was the same mistake as §3, made in the same subsystem an hour later. It fit the symptom,
which is not the same as causing it. The tell was in the write-up all along: the chain requires an
already-unparseable keyset, and nothing ever established one.

Read the two halves of this separately. The first is proved; the second was never established.

**Proved.** `EncryptedPrefs.kt:154` decides whether an unreadable encrypted store is repaired or
the app refuses to open it, and decides it by comparing `javaClass.simpleName` against the literal
`"InvalidProtocolBufferException"`. `mapping.txt` line 189149 of an actual release build:

```
com.google.crypto.tink.shaded.protobuf.InvalidProtocolBufferException -> a51:
```

The comparison therefore cannot match for any input in release. The branch is live in debug and
dead in every shipped build. Downstream: a store release declines to reopen throws
`EncryptedStoreUnavailableException`, `EnrollmentVault.stored()`'s `runCatching` catches it and
answers `null`, and `VaultOpenerAndroid.kt:36` reads `null` as `NotEnrolled` — a storage fault
presenting as "this device holds no key", which is the wrong advice and the advice that escalated.

`UnrecoverableKeysetTest` could not have caught this: it declares *its own* class named
`InvalidProtocolBufferException` (line 11, "the stand-ins below mirror Tink's shaded types"), so
the name always agreed. A test that validates a proxy instead of the artifact.

Fixed by a `-keepnames` rule, plus `checkRuntimeMatchedClassNames`, a Gradle gate that reads R8's
emitted `mapping.txt` and fails the build if a name in `runtimeMatchedClassNames` is renamed or
has gone missing. Verified red on the defect, green after the rule.

**Disproved: this is not what bit the reporter.** The chain above only fires if the keyset was
already unparseable, and nothing ever established that it was — the release build that failed was
reporting `DecryptFailed` from `PgpMimeReader`, not `NotEnrolled` from the vault. The `NotEnrolled`
reading in §1 step 2 was an *inference* from a wordless padlock, not an observation, and it was
wrong too.

**The decisive test was run** — by shipping `7eae633` and reading the sentence it produced. The
release build named its own failure and the name pointed straight at §0. No wipe, no logcat, no
state capture: the fix that made the app explain itself was also the diagnostic. That is the
cheapest thing in this whole document and it was available from the first hour.

## 4. Findings for other repos

**`kypost-for-Mac` — broken, independent of everything above.** Another session was working this as
of 2026-08-24.

`KyPost/Data/Networking/PgpPayloadClient.swift:59` sends `URLQueryItem(name: "message", ...)`. The
server reads `messageId` (`backend/internal/api/server_mail_attachments.go:20`) and 400s otherwise.
`HTTPClient.swift:91` maps 400 to `.badRequest`, which `PgpPayloadClient.result(for:)` does not
handle, so it falls to `default` → `.failed("this message could not be fetched")`, with a Retry
button that can never succeed.

It is a copy/paste from `webmailMessageURL` (`PgpMessageState.swift:163`), which legitimately uses
`message` for the webmail deep link. The app's own relay calls are correct —
`RelayMailSource.swift:463,475` both use `messageId`. Nothing tests the URL this builds.

**This ships on iOS too.** `SUPPORTED_PLATFORMS = "iphoneos iphonesimulator macosx xros xrsimulator"`.

## 5. Open work

### 5.0 "Store unavailable" is read as "never enrolled" in three places — **new, unfixed**

Found while proving §3.1, and independent of R8. `EncryptedPrefs.kt` states the contract in its own
words: *"Callers must treat this as unknown, never as empty."* Three callers do the opposite, and
each turns a transient storage fault into an accusation that the user never enrolled:

| Site | What it does |
|---|---|
| `EnrollmentVault.stored()` | `runCatching { … }.getOrNull()` swallows `EncryptedStoreUnavailableException` → `null` |
| `EnrollmentState.kt:20` | `catch (e: Exception)` → `EnrollmentStatus.NO_KEY` |
| `VaultOpenerAndroid.kt:36` | `null` → `OpenOutcome.NotEnrolled` |

§3.1's fix stops release *manufacturing* this fault, but any real one still arrives dressed as
"enrol this device". That is the sentence a user acts on by tearing down an enrollment, and §1 is
what that costs. Fixing it needs a decision this handoff does not make: what the read surface says
when storage is merely unavailable. It overlaps §5.2; do them together.

Now the highest-value item here, because §0 showed what a wrong sentence costs even when the code
underneath is fine.

### 5.1 ~~Why did enrollment fail silently?~~ — **CLOSED: enrollment never failed**

There was no silent enrollment failure. Enrollment worked; §0 is what broke, and it broke *after*
decryption succeeded. This item existed because §1 step 2 read a wordless padlock as `NotEnrolled`
and then everything downstream reasoned from that reading as though it were an observation.

The two mailbox wipes in §1 follow from the same mistake: an unexplained padlock, a guess at what
it meant, and a recovery action chosen to match the guess. Nothing was ever wrong with the
enrollment that was torn down twice to fix it.

Still worth doing, and now the only real item in this section:

**There is no logging anywhere in the Android read path.** `EncryptedMessageReader`,
`PgpPayloadClient` and `attemptDecrypt` emit nothing, so `adb logcat` was useless throughout. The
on-screen sentence from `7eae633` is currently the app's *entire* diagnostic surface for a failed
read. It was enough here, but it is one string and it only appears where a user is looking.

### 5.2 `NotEnrolled` covers three pairing failures — low priority

`EmailDetailActivity.encryptedReader()` returns null for three distinct reasons:

```kotlin
val pairing = ...pairingForAuthenticatedCall() ?: return null   // no pairing record
val deviceId = pairing.deviceId ?: return null                  // no device id
val deviceSecret = pairing.deviceSecret ?: return null          // no device secret
```

All three render as `NotEnrolled`, whose string sends the user to PGP enrollment. None is an
enrollment problem; the fix for all three is Reconnect. This misdirection is what sent the original
investigation down the decrypt path.

The fix: add `object NotPaired : ReadOutcome()`, return it from the null branch in `attemptDecrypt`,
add a string pointing at Reconnect, and handle it in `readFailureNotice` and `renderReadOutcome`.
`ReadOutcome` is matched exhaustively in exactly two places, both in `EmailDetailActivity.kt`, so
the compiler will find them. ~15 lines plus tests.

Deliberately low priority: `NotEnrolled` was **accurate** in this incident. Do not let its ranking
here suggest otherwise.

### 5.3 Release hygiene

The 0.3.3 GitHub build was tested and failed — but from §3, that was the unenrolled device, not the
artifact. No re-release is indicated. Recorded because it was seriously considered and rejected on
evidence; do not re-open it without new data.

## 6. Traps

- **Make the app say what went wrong, first.** `7eae633` was filed as a UX fix. It was the
  diagnostic: the release build named its own failure in one sentence and that sentence identified
  §0 immediately. Everything before it was inference over a wordless padlock, and two of those
  inferences were recorded as settled facts and were wrong. Cheapest tool in the box, reached for
  last.
- **A green unit test says nothing about the release build.** The suite runs unminified. It has no
  opinion about a class R8 deleted (§0) and none about a renamed one either, since a test that
  declares its own stand-in for a third-party type agrees with itself forever (§3.1). Anything
  loaded or matched **by name** has to be checked against `mapping.txt` —
  `checkRuntimeMatchedClassNames` is that check, and both bugs are in its list.
- **"It compiles" and "R8 emitted no missing rules" are not evidence.** Both were true while the
  release build was broken. R8 has no complaint about deleting a class nothing references; its
  silence was mistaken for a clean bill of health twice. Read the artifact.
- **A resource that names a class is a reference R8 cannot see.** `META-INF/mailcap`,
  `META-INF/services`, manifest attributes, layout XML. Grep the dependencies for these before
  assuming minification is safe.
- **"Reinstalling fixed it" may mean "not minifying fixed it".** A debug reinstall changes the
  build as well as the state, and the state gets the credit. See §1.
- **A wipe destroys the evidence.** Both mailbox wipes reset the pairing record and TLS pin, which
  was the state under investigation. If this recurs, capture state *before* attempting recovery.
- **"Unlock" is ambiguous on Android.** The app lock and the vault opener both prompt. A user saying
  "I unlocked my key" may mean either, and `VaultOpenerAndroid.kt:36` returns `NotEnrolled` before
  the vault prompt ever appears. This ambiguity cost most of a session.
- **Reconnect, never unpair.** `reconnectToServer` (`PushHomeViewModel.kt:72`, wired at
  `PushPairingActivity.kt:113`) clears the credential and pin and keeps the mailbox. Unpairing runs
  the purge, and a purge that cannot prove itself escalates to erasing the device.
