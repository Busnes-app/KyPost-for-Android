# Purpose

Owns production Android app code and resources.

# Ownership

- Code: `app/src/main/java/org/kysecurity/mail/`
- Resources: `app/src/main/res/`
- Manifest: `app/src/main/AndroidManifest.xml`

# Local Contracts

- Launcher supports `kypost://native-pair` deep links and QR pairing for native (non-Novu) push onboarding. The legacy `novu-pair` host (under the old `llamalabels://` scheme) and Novu relay path are removed entirely — the backend no longer serves them.
- Pairing proof material (subscriber id/hash, server URL, registration URL, pairing token, last-known device id, paired-at timestamp) is persisted in a Keystore-backed `EncryptedSharedPreferences` file (`SecurePairingStore`), not the plaintext DataStore used for history/sync.
- TLS pinning is TOFU over **the leaf certificate, and nothing else**. `NativeRegistrationClient` pins the first certificate the pairing handshake presented (`SpkiPinner.pinsForChain`). Pinning any issuer would admit every certificate that issuer signs, which for a public CA is every certificate anyone can buy — `CertificatePinner` passes when ANY chain member matches ANY configured pin. The cost is that a renewal minting a new key matches nothing and fails every call closed; the recovery is `PushHomeViewModel.reconnectToServer`, which clears the credential and pin WITHOUT deleting the mailbox. Do not reintroduce a "rolling window" of past leaves to paper over this: a key this device has never seen cannot be learned from a connection the pin itself rejects, so the window provably never held more than the leaf already in use. A `TlsPin` with an empty set is unconstructible and `pairingHttpClient` refuses one, because `CertificatePinner` passes vacuously when no pin is configured for a host. Installs predating the leaf-only rule hold a whole-chain set; `PushSyncCoordinator.narrowLegacyTlsPin` replaces it with the observed leaf on the next successful registration, exactly once. The capture is persisted BEFORE the pairing it protects (`attemptPairing`), mirroring `saveTlsPin`'s own marker-then-pin-then-cache order: a pin with no pairing is inert, while a pairing with no pin reads as `NeverPaired` and spends every credentialed call in the unpinned TOFU window until some later resync repairs it.
- A pinned client pins exactly the host it was built for; `CertificatePinner` passes every other host vacuously. So `PinnedCallFactoryProvider` hands back the `TlsPin` TOGETHER with the client, re-reading the pin INSIDE its lock, and `PinnedOrFallbackCallFactory` refuses any request whose host is not the pinned one. Every URL this app builds is same-origin with the pinned relay (`sameOrigin`, `resolvePullEndpoint`), so a mismatch means a re-pair landed under an in-flight call — refusing is the only answer that does not put device credentials on plain system trust. Never return a bare `Call.Factory` from the provider: it is the pairing of pin and client that makes the check possible.
- Recovering a credential is NOT unpairing. `PushRepository.resetPairingCredential` drops the pairing proof and TLS pin while keeping mail, contacts and keys; `clearPairing`/`unpairDevice` stay the destructive pair, for a deliberate unpair and for `attemptPairing`'s account-replacement branch. A rotated certificate or a stranded device secret must route to the former — "Reconnect to server" on the pairing screen — never the latter. Because it keeps the data, it must also record whose: `SecurePairingStore.clearPairing(rememberForReconnect = true)` writes a `ReconnectExpectation` in the SAME commit that removes the pairing. `savePairing` spends it, the destructive clear drops it, and a second reconnect with no pairing left to name leaves the first one standing.
- Registration and pull are each serialized by a coordinator-owned `Mutex` (`PushSyncCoordinator.registrationGate`, `PullSyncCoordinator.pullGate`), and the current pairing is read INSIDE the lock. Both are entered from several places at once — Firebase token rotation, UnifiedPush endpoint changes, foreground resync, the pairing screen, `PullWorker` — and both have read-then-write state that overlapping runs corrupt: every registration invalidates the previous `deviceSecret`, so a late reply persisting over a newer one strands the install; the pull cursor is read at the start and advanced at the end, so two runs notify the same batch twice. `NonCancellable` does not help with either — it guards a persist against cancellation, not against a competitor.
- A UnifiedPush endpoint and its WebPush keys (`push_state`) mean "the distributor gave us this", not "the server has it" — `transport` says what is registered. `onNewEndpoint` stores them on arrival, paired or not, AFTER the abandoned-wipe guard. It captures `ProcessState.generation()` in the callback, and `PushRepository.storeUnifiedPushEndpoint` checks it INSIDE the DataStore write, so a callback released after an unpair or wipe stores nothing. Revocations (`onUnregistered`, the gms `onRegistrationFailed`) capture it the same way and clear through the same checked write (`forgetUnifiedPushEndpoint(generation)`); a stale one clears nothing and skips its error update and FCM fallback, because the coordinator's queue outlives a graph invalidation. Every UnifiedPush callback goes through `PushSyncCoordinator.enqueueUnifiedPush`, one FIFO queue fed synchronously from the callback, so a revocation can never be overtaken by the endpoint it revokes. The store-on-arrival exists because the fdroid build has no other credential, and the distributor usually answers before pairing, so the pairing screen offers the UnifiedPush choice before a device is paired. `attemptPairing` and `resyncActiveTransport` prefer a stored endpoint on every flavor, choosing inside `registrationGate`. It is dropped by a successful non-UnifiedPush registration, by `onUnregistered` and the gms `onRegistrationFailed` (`forgetUnifiedPushEndpoint`, under the gate), by `clearPairing`, and by the wipe (see the DataStore rule below). `resetPairingCredential` keeps it: the distributor is still registered and re-pairing needs it. `UnifiedPushEndpointTest` pins this.
- A preferences DataStore is never removed by deleting its file alone. DataStore 1.1 keeps serving its in-memory cache for a file deleted underneath it, and a later edit re-reads the empty file, sees no change, and never refreshes that cache. The wipe relaunches in-process (`AppRestart`), so the old values stayed readable. Every deletion goes through `clearAndDelete` (`DataStoreFiles.kt`), which clears through DataStore and then deletes the file. Every store therefore has a `ReplaceFileCorruptionHandler`: without one, a malformed file throws on the clear and is never deleted, so the wipe fails on every retry. The wipe clears each store independently. That covers the wipe's `datastores` step (all three stores), the unpair purge (`mail_sync_state`, `contacts_state`) and `deletePlaintextMetadataStores`. A new DataStore must be added to `SecurityWipe`'s `dataStores`. `WipeResurrectionTest` and `AccountPurgeDataStoreTest` pin this.
- Whether a pairing is an account replacement is `isAccountReplacement(incoming, currentPairing, reconnectExpectation)`, never "is there a pairing right now". A reconnect leaves account-scoped data with no pairing, so the pairing alone under-reports; the marker is the second input. `attemptPairing` purges on it and `PushPairingActivity` picks the replace-warning dialog from the same answer (`PushRepository.replacesAnotherAccount`), so the warning cannot disagree with what happens. No pairing and no marker is a first-ever pairing: it must purge nothing.
- Account replacement is staged: `attemptPairing` registers FIRST and only then purges the account being replaced. Nothing may be destroyed before the replacement is proven, or an offline scan of a valid QR silently unpairs a working account. `clearPairing` returns the stores that survived the purge; a non-empty result during replacement refuses the new account and escalates to `SecurityWipe.wipeAndResetApp`, because no table carries a subscriber column and survivors are readable by whoever pairs next. Never let a purge failure become a log line.
- A PIN change is staged, not swapped in place. The verifier (`app_lock_secure`) and the wrapped device secret (`push_pairing_secure`) are different preference files, so no single `commit()` covers both. `SecuritySettingsActivity.changePin` writes the new wrapping via `SecurePairingStore.stagePendingSecret` **before** `setPin`, `resolveDeviceSecret` tries the live wrapping then the staged one, and the following `savePairing` promotes and clears the staged copy. Without staging, a process death between the two files sealed the secret under a key no surviving PIN derived, `needsCredentialRewrap()` could not see it (it answers a scheme-version question only — `deviceSecretIsStranded` is the one that detects this), and the relay's eventual 409 read to the user as "re-pair this device". Both of its key derivations go through `CredentialCipher.deriveKeysOrNull` and abort the change on null: an unreadable Keystore pepper is not a wrong PIN, and letting `PepperUnavailableException` out killed the process mid-protocol. Both abort points sit ahead of `setPin`, so there is nothing staged to roll back. `SourceRulesTest.credentialDerivationsHandleAnUnavailableKeystore` keeps raw `deriveKeys` out of every caller but `AppLockManager`.
- `PinPolicy` alone decides PIN length. A field that caps input sets
  `InputFilter.LengthFilter(PinPolicy.MAX_LENGTH)` in code; layouts never set `maxLength` on a
  `numberPassword` field (`PinLayoutLengthTest`).
- `AppLockStore.putCredentialSaltIfAbsent` is compare-and-set under a companion-scoped lock and never overwrites. It replaced a `check()` that threw `IllegalStateException` through `AppLockManager`'s PIN paths, which catch only `PepperUnavailableException`.
- Saving an attachment to Downloads is `security/AttachmentDownloads.kt`'s `saveAttachmentToDownloads`, not the detail Activity. Pass the raw sender name and MIME type: the sink resolves the safe type from both before sanitising the display name. The row is recorded in `DownloadedAttachmentLedger` BEFORE the first byte (it is the only handle a later wipe has on decrypted mail outside the sandbox) and is created `IS_PENDING = 1`, published only once the write completes; any failure deletes the row and KEEPS the ledger entry, since a row the delete could not remove must stay findable by the wipe. A decrypted-part save uses `OwnedAttachmentSave`: confirmation admits at most one owned snapshot before the executor hop; lock/destroy wipes a queued snapshot and makes its stale runnable refuse the write, while an already-started write keeps coherent ownership; completion or scheduling rejection wipes the remaining snapshot.
- `EphemeralAttachmentProvider.openFile` peeks rather than consumes: viewers that probe before reading open the same URI twice, and consuming on the first open made the attachment unreopenable. The TTL sweep is the single owner of pending bytes — the writer does not zero on completion, because that races a second reader streaming the same array. Every mutation of the pending map shares one monitor so the size budget is computed against a map nothing is concurrently draining. `PendingAttachment` sanitises `displayName` through `safeFileName` in its own constructor: the sender's Content-Disposition filename is served to the chooser as `OpenableColumns.DISPLAY_NAME`, so it gets the same treatment as the Downloads sink's name, at the sink rather than at each caller.
- `NativePairingDeepLinkParser` emits an already-resolved `registrationUrl`; it is never blank. A blank one is meaningless downstream (`readPairing` reads it as "no pairing at all", `register` rejects it), so resolution happens once at the parse boundary. `PushSyncCoordinator.syncAndPersist` still re-derives it for *stored* pairings — a different concern, guarding host divergence written by older builds.
- FCM token sync goes through the backend's native registration endpoint (`reg` from the pairing QR, or derived as `{srv}/api/notifications/native/register`) — there is no user-editable Server URL setting; `srv` is a required QR field and is always sourced from the QR.
- A device is marked paired only after the native register call returns success (`ok:true`/`synced:true`); a QR scan alone does not pair the device. `503` from the registration endpoint means the backend is missing `PAIRING_SECRET` (a persistent misconfiguration) and is not retried.
- Incoming FCM payload parser contract keys are `messageId`, `senderName`, `emailSubject`, and `keywords`/`Keywords` (either casing is accepted — the server sends the capitalised one, everything else is camelCase).
- Both delivery paths bound relay-supplied strings in ONE place, `PushPayloadParser.sanitize` (messageId 256, sender/subject 512, 32 keywords): `parse` for push, `PullNotification.toPushPayload` for pull. The relay picks a device's `deliveryMode`, so a pull path that skipped those bounds made them optional — and `push_state` re-serialises its whole history on every append, so oversized strings there are an OOM the app hits before it can delete them. A new delivery path must call `sanitize`; `PullNotificationTest` asserts the two paths agree.
- Pull is also the push-mode heartbeat (`PullSyncCoordinator`, server issue #137 option 1). The server queues every notification in both delivery modes and never flips the mode itself, so a device on a dead relay recovers only by polling. `PullWorker` is armed whenever the device is paired (15-minute floor, both modes) and `pullOnce()` decides: PULL mode always polls; PUSH mode polls only once no push has arrived for `PUSH_QUIET_THRESHOLD_MS` (3 h, a constant), counted from `lastPushReceivedAtEpochMs`, which both messaging services stamp on every delivered message, or from the last registration when no push has ever arrived. A PUSH answer from the pull endpoint is NOT "stop polling". Pulled entries take the same MFA-first decision as pushed ones (`IncomingPushRouter.route(PullNotification, now)`), and a pulled mail is only alerted when `appendPayload` reports it new, so a message push already delivered is not shown twice. A heartbeat's cursor can be months stale and history holds 30 rows, so a heartbeat drops entries older than twice the threshold while still advancing the cursor past them. `PullHeartbeatTest` pins all of this.
- MFA push 2FA: an incoming FCM data payload with `type: "mfa_challenge"` and `challengeId` is parsed by `MfaChallengePayloadParser` (distinct from the mail payload parser) and shown via a separate high-importance notification channel (`PushNotificationDispatcher.showMfaChallenge`). The notification carries **no Approve/Deny actions and no challenge detail** — it is tap-to-open only. Notification actions fire from the lock screen with no authentication, which let anyone holding the powered-on device approve a sign-in and bypassed the PIN/biometric/lockout/wipe apparatus entirely; the `MfaResponseReceiver` that backed them has been deleted. The decision happens only in `MfaApprovalActivity`, which re-authenticates via `BiometricPrompt` (`BIOMETRIC_STRONG or DEVICE_CREDENTIAL`) and re-checks `MfaChallengeTracker.isPending` before either button does anything. `MfaResponder.respond` POSTs to `{serverUrl}/api/mfa/push/respond` via `MfaResponseClient` using the same device-id/secret pairing credential as native register/pull. `MfaChallengeTracker` is SharedPreferences-backed, not in-memory: FCM delivers to short-lived processes, so an in-memory record was usually gone before the user tapped. Each challenge gets its own notification id — coalescing distinct challenges onto one id meant answering either cancelled both.
- Push notifications are shown via Android notification channel and copied into in-app history preview. While `AppLockManager.locked` is true, title/text are replaced with a generic string and visibility is `VISIBILITY_SECRET`; while Hostile Location Protection is on, history is held in memory only and never written to the `push_state` DataStore.
- Every screen except `UnlockActivity` and `MfaApprovalActivity` extends `security.LockedActivity`, which redirects to the unlock screen in `onStart` (and `finish()`es, so nothing is left underneath to reveal with Back) and applies `FLAG_SECURE`. Do not extend `AppCompatActivity` directly for a new screen. Both exceptions gate on `SecurityWipe.startupVerdict` themselves, and a gate that returns from `onCreate` without `finish()` still starts and resumes the activity — so each carries a stand-down flag (`redirectedToUnlock`, `awaitingStartupVerdict`) that every other lifecycle callback touching a `lateinit` view must honour.
- A dialog is a separate window and does not inherit the Activity's `FLAG_SECURE`. Show every
  `AlertDialog` with `.create().showSecurely()`; `SourceRulesTest.alertDialogBuildersAreShownSecurely`
  refuses a builder chain ending in `.show()`.
- The startup notices (credential reset, stranded downloads) are one-shot **per process**: the latch is spent when the dialog is built, and the pref behind it is cleared only by the user tapping OK. They are therefore claimed through `claimNotice` *after* the unlock redirect, and never by a screen that is going away — `MainActivity` sets `showsStartupNotices = false` because it routes on and finishes. A screen that finishes itself must do the same, or the notice (including "your cached mail is gone") dies unseen for the rest of the process. `StartupNoticeLatchTest` covers the gate.
- Android 13+ notification runtime permission is requested from launcher UI.
- `signon/` is KyIdentity sign-in through KyAuth's AccountManager account. Details:
  - `AuthenticatorPin`: `decide` is the pure half. The button and the activity both require exactly one authenticator of type `org.kysecurity.identity`, package `org.kysecurity.authenticator`, one signer, and every certificate in KyAuth's signing history within the pinned SHA-256 set (`containsAll`; fail closed). Trade-off: a rotation makes KyAuth untrusted until KyPost pins the new certificate too. The manifest `<queries>` entry lets KyPost read KyAuth's certificate. Only debug builds honour Gradle property `kypostDebugKyAuthCert` (64 lowercase hex, validated at configuration time) as one extra digest, for a debug-signed KyAuth.
  - `KyIdentitySignOnClient` is pure JVM (no Android imports, never logs the ID token): `GET /api/auth/sso-config`, then `POST /api/auth/native/signon {idToken}`, answered like `review-pairing`. Error bodies are bounded and sanitised; a 403 body is shown only if plain text, first line, at most 200 chars. It refuses a deep link whose host differs from the relay host.
  - `KyIdentitySignOnActivity`: one account is used directly; zero or several go to `AccountManager.newChooseAccountIntent`, used only to pick (accounts are created in KyAuth, so no add-account fallback). Cancelling the chooser or KyAuth's prompt leaves the user on the sign-in screen with no message, except a chooser opened with zero accounts, which sets the `kyidentity_signon_no_account` hint. The account's `server_url` must equal the config's `issuerUrl` (`IssuerMatch.sameIssuer`, pure; both sides must parse; the error shows full canonical origins). `getAuthToken` passes option `KyIdentitySignOn.OPTION_ORIGIN` (`org.kysecurity.identity.origin`), the canonical origin (`relayOrigin`: scheme, punycoded lowercase host, port unless 443) of the URL the client connected to, parsed by the same `pairingEndpoint` path; an unusable URL is refused locally before `getAuthToken`; KyAuth's prompt names the relay host and binds the token to it, and refuses a missing or insecure one with `IllegalArgumentException` ("A secure relay address is required"), shown via the sanitised path below. `getAuthToken` and the exchange run in `KyPostApp.appScope`, not `lifecycleScope`: KyAuth's full-screen prompt stops KyPost, and with the "Immediately" lock (or a >30 s detour) `LockedActivity` redirects to Unlock and finishes this activity, which would cancel the flow and drop the approved token. The result (the parsed `PairingData`, never the token) goes to the process-scoped, single-use `PendingPairingLink` (cleared on `SecurityWipe` via `ProcessState`); `PushPairingActivity.onResume` takes it and runs `confirmAndApplyPairing`, so the host-confirm dialog still applies. If the activity is alive it also finishes and shows errors as status text; if destroyed it does neither. The token stays a local. The activity is `configChanges`-protected against rotation.
  - Flavors: KyAuth pins only `org.kysecurity.mail`, so the button shows only when `BuildConfig.APPLICATION_ID` is that and the authenticator pin passes. `github` and `fdroid` hide it until KyAuth pins them. KyAuth authors its own `AuthenticatorException`, `UnsupportedOperationException` and `IllegalArgumentException` texts; the activity shows their first line (at most 200 chars). Other failures show a generic string.
  - Device checklist (unverified on hardware): chooser with zero and with several accounts; cancelling KyAuth's prompt; visibility of an account KyAuth created before KyPost was installed; `getPackageInfo` on KyAuth succeeding through `<queries>`; rotation mid-flow; prompt shows the typed relay host; "Immediately" lock setting round trip (KyAuth prompt, unlock, pairing confirm dialog appears); 30 s grace with the chooser to KyAuth pairing detour; github-flavor refusal (button hidden).
- After a registration succeeds from the pairing screen (`PushHomeViewModel.paired`, a conflated
  channel, so a screen stopped by KyAuth's prompt still receives it), `AppLockOffer` suggests an
  app lock once per install, and only if none is set. It is never forced: "Not now" is a final
  answer. The offer is spent when shown, committed synchronously, so rotation or Back cannot make
  it nag. Accepting opens Security settings.
- `MainActivity` is a router, not a home screen: it sends paired devices to `InboxActivity` and
  unpaired devices to `PushPairingActivity`, then finishes itself. It passes `EXTRA_MESSAGE_ID`
  from push notifications to `InboxActivity` to
  enable deep-linking directly to a new email. It does not manage pairing, token sync, or push
  history UI — that lives in `push/PushPairingActivity`, reached from the Settings hub.
- The device must be paired via `PushPairingActivity` to use relay mail; there is no separate
  mobile login or mail-password form. Never build UI for the server's web-only mail configuration
  endpoints; an unconfigured relay is an empty state, not a form.
- `PasswordPairingActivity` is the review-only convenience path: it sends a server URL and
  one-time username/password to `/api/notifications/review-pairing`, clears the password field,
  then feeds the returned deep link through the ordinary parser, confirmation, registration,
  TLS-pin, and credential-storage flow. The relay exposes that endpoint only when its
  `REVIEW_PAIRING_USERNAME` flag names a disposable account or a trailing-`*` username prefix;
  this is not a second mobile auth mode. Normal builds hide its entry button; build the Play
  review artifact with `-PenableReviewPairing=true` to expose it.
- `mail/RelayMailSource` calls relay endpoints over OkHttp with device-id/device-secret headers.
  `mail/MailRepository` writes results into the Room cache (`data/AppDatabase`,
  `EmailDao.replaceFolderSnapshot`) and is what `InboxActivity`/`EmailDetailActivity`/
  `ComposeActivity` call.
- Client-custody draft handoff on an enrolled device encrypts and signs the complete draft to the
  locally unsealed account key through `ClientEncryptedDraftSaver`; the relay receives only `to`
  and `pgpDraft`. Protected To/Cc/Bcc/Subject, body and attachments travel inside the ciphertext;
  the outer MIME has To and a placeholder Subject, with no Cc/Bcc. Bootstrap keys and recipient
  discovery are not inputs to self-encryption. Consent names the exposed From/To/date metadata.
  Initial restored/prefilled HTML seeds the synchronous body mirror before the editor export, so
  an immediate recreation cannot replace it with an empty body.
  The encrypted transport requires JSON `ok:true`, but this is not a receipt proving ciphertext
  was stored by an older relay. The composer therefore stays available even after save and browser
  launch succeed; only the user's normal discard/send action removes it. A modal
  prevents edits during saving, and Activity destruction cancels its vault prompt.
  Unenrolled devices open webmail without transferring any composition; unknown custody refuses
  the operation. Compose never calls the plaintext `saveDraft` transport. Retry after a successful
  save but failed browser launch can create another draft: the relay exposes no draft ID/upsert.
- **`MailRepository` is the one synchronization boundary: the source returns facts, the repository
  decides when they become durable.** Two rules follow from that, and both were once broken.
  1. `RelayMailSource.fetchInbox` READS the cursor (to build `since`) and returns the next one as
     `MailFetchResult.checkpoint`; it must never write it. `MailRepository.refreshFolder`
     reconciles into Room FIRST and commits the checkpoint SECOND. Room and DataStore cannot share
     a transaction, so the ordering is the guarantee: a crash in between replays the window (upserts
     and deletes are idempotent), whereas advancing first made the relay skip that mail until the
     daily since=0 self-heal — a day of silently missing messages. The delta itself lands through
     `EmailDao.applyFolderDelta`, one transaction, so it cannot half-apply.
  2. HTTP 200 from `/api/inbox/actions` is transport success, not operation success: the relay
     answers 200 with per-id `failed[]` (docs/Mobile_Mail_Relay.md Part 2). `MailOutcome<MailActionOutcome>
     .appliedTo(id)` is the only gate on touching the local row — archive/spam/delete/move drop the
     cached row and `markRead` sets `status`, both **after** the relay confirms that id, never
     before. A rejection becomes `MailOutcome.ActionRejected`, not `UpstreamFailure`: the request
     did reach the server, and "Couldn't reach the mail server" sends the user to check a
     connection that is fine. `processed` is a count rather than a list, so `processed < 1` with an
     empty `failed[]` is also treated as rejected — an unconfirmed operation must not delete a
     locally visible row. The *display* is optimistic, Room is not: `PendingMailActions`
     (in memory, session-scoped through `ProcessState`) makes `cachedEmails` hide a row with an
     archive/spam/delete/move in flight and show a row read while the open's `markRead` is in
     flight, and forgets both when the call fails. Each key holds its latest `PendingMail`, so an
     earlier claim finishing never clears a later one's overlay. `markUnread` (KyPost-Server #350),
     from the detail screen's Mark unread button and the inbox selection's overflow (Mark read /
     Mark unread, one call per row; long-press stays select), takes no overlay: neither explicit
     action repaints the row until the relay confirms, and both are session-guarded like the rest
     (the generation is captured when the user acts). A server without the action answers 400
     "unsupported action", which is toasted as is. The open's markRead (claimed with `beginRead`
     before it is queued), the detail button and the inbox selection all go through
     `ReadStateLane.ordered`, a process-wide chain: each read-state change waits for the one
     requested before it (30 s at most), across screens and reopens. The pool has two threads, so
     without it a read still in flight could land after the unread and win; it also means the
     open's read overlay is gone before a later unread runs. The row repaint matches folder as well
     as id. A confirmed removal stays in `removed`, and refresh and older-mail writes
     drop those ids: an IMAP UID is never reused in its mailbox, so a refresh that read the window
     before the removal must not resurrect it. The inbox puts a row whose swipe failed back in
     place with a Retry snackbar. A row action carries the `MailAccount` (subscriberId, serverUrl)
     its rows were read under; `RelayMailSource.performAction` sends nothing when the pairing it
     builds the request from is a different account. The inbox drops a failure (no row, no Retry)
     unless the session generation captured at the swipe is still current and the active pairing
     (read on the worker, since the screen's account only updates on repaint) is still the row's
     account. Every removal and the open's read is claimed on the caller's thread before it is queued
     (`MailRepository.beginRemoval`/`beginRead` return a `PendingMail` carrying the generation
     then): the overlay shows at once, the action is not sent if that generation has ended, and a
     completion writes the removal set or Room only while it is current, under the lock the reset
     takes. Refresh filtering and writes take that same lock. A task the executor refuses or
     discards unrun calls `abandon`. `PushRepository.clearPairing` holds mail work
     (`MailBackgroundExecutor.quiesce`) until the outgoing pairing is cleared. A failed read
     notifies `setOverlayListener`, and the inbox repaints from the cache (a failed removal is the
     inbox's own failure path to restore or drop, never a cache repaint); it also paints the
     cache before every non-pull network refresh, so a row opened and marked read shows read at once.
- **Older mail and reliable deltas (KyPost-Server #348/#349; each part degrades to the old
  behaviour on a server without it).** Every `/api/inbox` request uses `WINDOW_LIMIT`: the relay
  keeps one window and cursor per `limit`. `EmailEntity.inWindow` is false for rows older than the
  window — paged in by "Load older mail" (`MailRepository.loadOlder`, `before=`) or reported
  `agedOut` — and snapshots prune only `inWindow` rows, so the daily since=0 resync never drops
  paged-in mail. A snapshot first takes absent rows dated before its oldest row out of the window
  (they aged out unreported, e.g. under a forgotten cursor); it prunes only absent rows inside its
  date range. `removed` still deletes any row. A page row is metadata only, so a held row keeps
  its body and PGP/attachment flags and takes only status and labels. A body opened on an
  out-of-window row is never cached: a paged row has no `pgpEncrypted`, which is what
  `clearServerDecryptedBodies` keys on at enrollment. A delta with `hasMore`
  pages down from `nextBefore` until a page holds an id Room already had, stores those rows, and
  only then commits the cursor. The window and the walk are written in one Room transaction
  (`EmailDao.inTransaction`). A failed or contradictory walk (no `nextBefore`, a page without
  `hasMore`) stores nothing, not even the window, and keeps the old cursor: any stored row would
  count as held, and a retry after newer mail would stop at it and commit past the gap. `delta: false` answering a
  cursor is a snapshot. A `before=` answer without `hasMore` is a server that ignored it; it is
  refused, never stored. A storage failure reading the row to page from or storing a page is reported as
  `OLDER_MAIL_NOT_SAVED`, never thrown, and keeps the paging frontier and the footer for a retry; only an empty folder hides it. Known gaps: the relay tracks deletions only inside its window, so an
  out-of-window row stays until the user acts on it; such rows are not healed by the daily resync
  after a UIDVALIDITY reset; encrypted mail stored from a page (older mail, or delta overflow)
  lacks its PGP flags because the page carries none, so it opens through `/api/mail/body` with no
  webmail handoff; overflow paging stops after `MAX_OVERFLOW_PAGES`.
- **`emails` is keyed on (folder, messageId), not messageId.** The relay's id is an IMAP UID,
  unique only within one mailbox, so INBOX and Archive can both hold `42`; under the old
  single-column key a refresh of either folder overwrote or relocated the other's row, and a
  removal in one folder deleted the other. Every per-message DAO statement takes the folder.
  Still not UIDVALIDITY-aware — the relay does not expose it and a client cannot invent one; the
  daily full resync rewrites the window, so id reuse self-heals within a day. See `EmailEntity`.
- PGP state on relay inbox rows: `pgpEncrypted`, `pgpSigned`, `pgpVerified`, `pgpSignerFingerprint`,
  `pgpDecryptError`. All are `omitempty` server-side, so the Kotlin defaults (false/"") are the
  contract for a message with no OpenPGP content, not an unknown state. `pgp.PgpMessageState` is the
  single place the rule lives: `pgpEncrypted` with an EMPTY `pgpDecryptError` means the account's key
  is end-to-end protected — the server holds no key, there is no body, and whether this device can
  read it depends on its enrollment state, below; a NON-empty `pgpDecryptError` means the server
  tried and failed, which is a different state with a real error to show; `pgpEncrypted` with a body
  means the server decrypted it, which `EmailDetailActivity` surfaces rather than rendering silently,
  because the user should be able to tell the server read their mail.
  **There IS an on-device private key, and this replaced the earlier "deliberately none" contract.**
  The device enrollment ceremony seals the account's PGP private key into a StrongBox/TEE AES-GCM
  envelope with `setUserAuthenticationRequired(true)` (`pgp/EnrollmentVault`), and no passphrase is
  ever typed on the phone — which is what made the old objection ("the phone never learns the
  account password") stop applying. `pgp/EncryptedMessageReader` unseals it through
  `pgp/VaultOpener`, holds it in `pgp/EnrollmentSession` for the configured lock window, and
  decrypts client-protected messages locally. So `CLIENT_PROTECTED` no longer means "cannot be read
  here": it means "not readable here **unless** this device is enrolled and unlocked". Webmail
  remains the fallback for every device that is not.
  A key rotation merges the newly enrolled secret-key collection first, then every retired primary
  identity; a matching primary also recovers any historical subkey absent from the new collection.
  For the same fingerprint, retain a nonempty historical private packet with incoming public
  metadata. Merge never extracts private keys or runs incoming password KDFs: a small Argon2
  packet can request more memory than the entire app budget. A corrupt nonempty historical
  packet requires explicit recovery; re-enrollment does not silently replace it.
  Invalid, empty, oversized, or over-count material fails the entire merge, preserving the old
  vault rather than sealing a partial history. `MemoryBudget` owns the input, output, ring-count,
  and separate enrollment-peak ceilings. Secret-key consumers parse packet order through
  `orderedSecretKeyRings`; Bouncy Castle's collection iterator returns map order, which cannot
  choose the current ring for signing or own-public-key derivation. That parser accepts exactly one
  complete private-key armor block and checks the underlying bounded input has only whitespace left
  after decoder EOF; Bouncy Castle accepts several whitespace-prefixed dash terminators, so a
  hand-written approximation of its footer grammar is not sufficient.
  Re-enrollment opens that existing vault through the live enrollment Activity and seals only a
  successful current-first merge. `EnrollmentVault.stored()` returns null only when no record exists
  in either format; incomplete/corrupt/oversized records and read errors propagate to
  `AndroidVaultOpener` as `Failed`. Only `NotEnrolled` permits a current-only seal; cancellation,
  open failure, a lost opened session, or merge refusal must leave the old vault and server state
  unchanged. A successful seal wipes both plaintext arrays and clears `EnrollmentSession` before
  cache deletion or the enrollment report. Both enrollment biometric operations are owned by the
  live Activity: destruction explicitly resolves a pending open or seal exactly once, and a late
  callback from the destroyed Activity cannot write the session or vault.
  The sealed record is one file, `files/device_envelope.bin` (version byte, IV, ciphertext),
  replaced by writing `device_envelope.bin.new`, syncing it, renaming over the old record, and
  then fsyncing the directory: a rename is metadata, and without the directory sync an unclean
  shutdown inside the ext4 commit window reverts it to the previous record after the ceremony has
  already acknowledged enrollment (`scripts/vault-crash-check.sh` reproduced exactly that).
  `EnrollmentVault.store` reports false on any failure and leaves the previous record and key
  untouched; `commitSeal` maps that to `SealOutcome.Failed`, so `Sealed` means durable. androidx
  `AtomicFile` is not used because its `finishWrite` logs a failed sync or rename instead of
  reporting it. Vaults sealed before this format live in the `device_envelope_secure` encrypted
  preference file: they are read in place, never rewritten on unlock, and retired only after a
  replacement file is on disk. `destroy` removes the file, its pending sibling, and the legacy
  store. `ensureKey` regenerates freely when no record exists. While a record exists it regenerates
  only over a Keystore alias whose absence is corroborated: three `containsAlias` reads with the
  encrypted-prefs backoff all answer absent, and `keystoreAnswers()` (a master-key round trip)
  proves the Keystore is answering rather than briefly unwell. That is what removing the lock
  screen leaves behind, and the record such a key sealed can never open again, so it is cleared
  first. A present key that will not inspect or no longer matches its spec, an uncorroborated
  absence, or a store that cannot be read, fails closed while a record exists: only "Remove from
  this device" may discard it. The one unavoidable loss is a legacy preference keyset `openEncryptedPrefs` proves
  unrecoverable; that record was already unopenable.
  Device envelopes carry an explicit version that `parseDeviceEnvelope` reads once and threads
  through `DeviceEnvelopeFields`: the HKDF info and AAD prefix are both `kypost-device-envelope/v<n>`
  from that field, so a v3 envelope can never be reopened under the v2 domain. Callers pass the
  versions they admit; `EnrollmentCeremony` admits both, and a v3 envelope is opened only
  against the delivery record the server returned beside it. v2 parsing is byte-compatible with what shipped
  (a quoted version string still opens; the on-curve check stays with the Keystore agreement).
  The pre-parse bound is the largest cap among the versions the caller admits, so a v3-only
  caller never hands the JSON parser more than the v3 cap. v3 is checked before any key work:
  the serialized envelope is at most
  `MemoryBudget.PGP_DEVICE_ENVELOPE_V3_BYTES` of UTF-8 (measured without copying), exactly the
  five fields, canonical padded standard base64, a 65-byte uncompressed point that is on P-256 and
  not the identity, a 12-byte IV, and a ciphertext longer than its 16-byte tag. The v3 AAD binds
  the device ID unchanged (nonempty, at most 65,535 UTF-8 bytes, lengths in bytes) and a
  40- or 64-digit uppercase fingerprint supplied by the caller, never read from the envelope.
  `pgp/PgpKeyring.kt` parses `kypost-pgp-keyring-v1` plaintext into a validated holder without
  touching the vault or session: at most `PGP_KEYRING_JSON_BYTES`, strict UTF-8, no duplicate JSON
  keys (kotlinx keeps the last silently, so `jsonHasDuplicateKeys` scans first), exactly the five
  ring fields and two-or-three member fields, a positive safe-integer generation, fingerprints
  compared case-insensitively and reported uppercase, at most 16 members and 256 inventory
  entries. Each member is one unprotected private ring whose primary fingerprint matches its
  entry, checked from the packet header before any extraction so no attacker-chosen passphrase KDF
  runs, with every subkey bound by the primary; the fingerprints derived from all packets must
  equal the declared inventory exactly, and exactly one member is the active one. The caller
  passes the active fingerprint it committed to in the AAD and the ring must name that same key:
  every AAD input is public, so a self-consistent ring alone could name any active key its author
  controls. Historical
  members stay for decryption and are not signers. The holder keeps the original plaintext bytes
  and each member's armor for later sealing and wipes those on `wipe()`; the JSON String, element
  tree and Bouncy Castle packet objects cannot be zeroed and are documented as transient.
  `PGP_KEYRING_IMPORT_PEAK_BYTES` accounts for that import beside, not instead of, the legacy
  enrollment peak. Legacy armor keeps its own parser and limits.
  The sealed record carries its plaintext kind as its format byte (`VaultRecordKind`: 1 legacy
  armor, 2 keyring); preference records are legacy by definition, and an unknown byte fails
  closed. Nothing inspects plaintext to choose a parser: `installOpenedMaterial` installs by the
  declared kind, and a keyring record that no longer validates installs nothing and opens as
  `Failed`. `EnrollmentSession` holds one thing at a time — legacy armor as a wipeable
  `CharArray`, or one validated `PgpKeyring` — and exposes only scoped access: `withDecryptionKeys`
  (every member, so history and hidden recipients decrypt), `withSigner` (the explicit active
  member, or a legacy collection's first ring; null means unusable and callers must fail, never
  substitute a historical member), `withLegacyArmor` (legacy only, for the merge) and
  `withKeyring`. There is no raw accessor, so a keyring can never reach the armor parser.
  `PgpDecryptor` tries every encryption-capable key for a hidden (zero) recipient key id;
  `PgpEncryptor` signs only with the given ring's own unrevoked, unexpired signing key.
  `importKeyring` is the local v3 import, pure and transport-free: validate the whole ring against
  the AAD's active fingerprint, then open the previous vault to establish replacement safety,
  then seal the original bytes as a KEYRING record, then install the session from those committed
  bytes, then `onLocalComplete`; any acknowledgement caller hangs off that callback and nothing
  earlier. Identical bytes replay without resealing only when a KEYRING record is on disk, read
  through the unauthenticated `sealedKind` probe: a held session proves nothing about the disk,
  since teardown and key invalidation delete the record without clearing the session, so a held
  ring with no record behind it is sealed like a fresh import. Any other previous material — a
  different ring or legacy armor — is `RefusedIncomparable` and kept, because equal inventories
  prove nothing about certifications or revocations and the replacement contract is not shipped.
  A keyring record binds its format byte into the GCM tag as AAD on seal and open; legacy records
  predate that and stay AAD-free. A
  legacy ceremony over a held keyring refuses the merge (`withLegacyArmor` is null) and leaves the
  record. `probeEnrollment` reports a keyring record as `ENROLLED_KEYRING`: `isEnrolled()` for this
  device's own reading, signing and settings row.
  **Live v3 (KyPost-Server #201, #210, #212).** `EnrollmentClients.publishKey` advertises
  `envelopeVersions: [2, 3]`; omitting the list resets the server's claim to `[2]` and the browser
  then refuses to seal v3, so never drop it. The envelope fetch carries `DeliveryMetadata`
  (`version`, `fingerprint`, `materialGeneration`, the keyring's `primaryFingerprints` and
  `keyFingerprints`), absent only from a server older than #210. The ceremony opens a v3 envelope
  only with a v3 delivery record whose fingerprint is the checked identity, and `importKeyring`'s
  `validate` rejects a ring whose generation, member set or inventory differs from that record
  (`KEYRING_REJECTED`, nothing sealed). Every acknowledgement is an `EnrollmentReport`:
  `NotEnrolled` (which also makes the server forget its delivery record), `Legacy` (the bare
  boolean; a converted account refuses it with 409), or `Keyring(materialGeneration, fingerprint)`
  sent with `envelopeVersion: 3`. The server matches a keyring acknowledgement against the
  delivery it recorded for this device, so a bare boolean is never sent for a keyring record and
  a 409 (`EnrollmentCallResult.Conflict`) is never retried. The sealer stores the acknowledgement
  beside a keyring record (`EnrollmentVault.storeKeyringAck`, plain preferences: both values are
  what the owner's device listing shows); `store` and `destroy` clear it, and
  `enrollmentReportFor` gives the worker `Keyring` from it, or null (say nothing) when a keyring
  record has no stored acknowledgement. `NotEnrolled` makes the server forget its delivery record,
  so the worker sends it only on a proven loss: `KEY_INVALIDATED` (the Keystore's own verdict) or
  `NO_BLOB` with the teardown marker `EnrollmentTeardown.destroy` leaves in the same preferences
  (`markTeardownReport`; `store` clears it, the worker clears it only when the report landed or no
  device row remains (`teardownReportSpent`: Ok, Unauthorized, NotFound), never on a transient
  failure even past the attempt ceiling,
  and the account-scoped purge clears it because a dropped pairing has no device row to correct;
  `clearKeyringAck` removes only the two acknowledgement keys so key regeneration and `destroy`
  leave the marker alone).
  `NO_KEY` (the catch-all probe exception) and an ordinary `NO_BLOB` say nothing: the worker runs
  on every unlock, and a device awaiting its first delivery looks exactly like `NO_BLOB`. A 409 on
  the ceremony's own acknowledgement is `ACKNOWLEDGEMENT_REFUSED`, a terminal failure whose copy
  says the record was saved but the account moved on; it is never `Enrolled` and never retried.
  `ClientEncryptedMessage.materialGeneration` is the held keyring's generation (null for legacy
  armor) and rides on `/api/mail/send-pgp`; the relay maps 409 `reenrollmentRequired` and
  `pgpStateChanged` to messages that say to enroll the device again. Still gated server-side:
  replacing a different ring already on the device (`RefusedIncomparable`), ring merging, readback.
  Hostile Location Protection destroys the envelope and is the mode in which none of this exists.
  `pgpRowMarker` marks inbox rows for the two states that yield nothing readable (🔒 client-protected,
  ⚠ decrypt failed) and deliberately leaves server-decrypted rows unmarked — those open normally, so
  a marker would sit on most rows of a server-mode mailbox carrying nothing actionable. `EmailAdapter`
  spells those two out in the row's `contentDescription`, because screen readers announce emoji
  inconsistently, together with unread and attachment state (the dot and 📎 have no voice) and the
  preview line, which the row-level description would otherwise hide. Inbox rows also carry Archive
  and Delete accessibility actions, the screen-reader form of the swipes.
  A failed signature or a CHANGED signer key (`PgpSignatureState.KEY_CHANGED`) outranks both with
  ⚠. `SIGNER_UNKNOWN` deliberately does not mark: it is the ordinary state for a correspondent not
  yet in the address book, and a glyph on most rows carries nothing actionable.
- `PgpSignatureState` has eight values, not a verified/unverified pair: `NONE` (no opinion expressed),
  `UNSIGNED` (local decryption found neither a packet signature nor a declared PGP/MIME signature
  wrapper; it gets an informational detail notice but no inbox warning, even when the relay resolved
  no sender), `VERIFIED_CONFIRMED`
  (a key bound to the sender that the user
  confirmed out of band — the only state that claims identity), `VERIFIED_SEEN_BEFORE` (a bound key still matching its TOFU
  pin, but never confirmed — most keys arrive by Autocrypt harvest, so this claims only continuity,
  "same key as last time", not who they say they are), `SIGNER_UNKNOWN` (no key bound to this sender
  at all — an ordinary correspondent not yet in the address book, a key that rotated before harvest,
  and a forged `From` are locally indistinguishable, so this is not an accusation), `KEY_CHANGED` (a
  key IS bound to this sender and no longer matches its TOFU pin — the one alarm worth raising), and
  `INVALID` (signed, but it does not verify against the bound key). **The client parses no address out
  of the `From` header at all.** `senderAddrSpec` and its helpers were deleted after a differential
  harness found 27 divergences from the server's parser across 111 adversarial headers — worst, an
  RFC 5322 comment like `Bob (Eve <eve@evil>) <bob@x>`, where the client bound `eve@evil` and the
  server binds `bob@x`, letting any contact forge a verified badge for anyone. The server now ships
  `signerKeys` already narrowed to the sender it resolved (`pgp/SignerBinding.signatureStateFor`,
  consumed by `pgp/EncryptedMessageReader`). Root and nested `multipart/signed` wrappers with
  `protocol=application/pgp-signature` suppress UNSIGNED. They are detected, not verified: without
  a packet signature the verdict is UNCHECKED ("Signature not checked"), including malformed
  signature contents. This message-level notice remains visible even without a resolved sender.
  Existing sender-bound packet verification remains authoritative when present.
  `EncryptedMessageReaderTest` covers real encrypted root/nested signatures and invalid declarations.
  Do not reintroduce a client-side `From` parser to "wire up" that narrowing yourself — a second parser deciding the same binding is exactly the defect that
  was removed. `signerKeyIdsOf` also excludes revoked and expired OpenPGP keys before a signature can
  become a trusted state, and `PgpDecryptor` caps decompressed plaintext at 32 MiB before allocation.
- **The account's own PGP identity is never in the contacts database.** `ContactEntity.pgpKey` — even
  on the self-contact (`isSelf = 1`) — is an ordinary contact field, written only when a key is
  attached to a contact by hand or by the QR scan; the account's real identity lives server-side.
  Two helpers exist because of this and are the only correct readers: `contactHasLinkedPgpKey`
  (badge: self also counts as linked when `pgp.hasPgpIdentity` says so) and
  `pgp.ownFingerprintFromBootstrap` (the fingerprint `PgpKeyActivity` shows beside the user's own
  QR, from `GET /api/pgp/bootstrap`'s `publicKey`, hashed locally by `PgpFingerprint`). Reading
  `contactDao().getSelf()?.pgpKey` for either is the bug both replaced — it is empty for
  essentially every user. Do not source that fingerprint from the QR token instead: `/api/pgp/qr/key`
  is single-use server-side, so fetching our own key with it burns the code being displayed.
  Never render the server's own `fingerprint` field for either side of the exchange; it is a claim
  beside the key with no cryptographic tie to it.
- Client-protected messages offer "Open in webmail" via `pgp.webmailMessageUrl`, which builds
  `{serverUrl}/read?mailbox=&message=` — the same route a web push click uses, so no server change
  backs it. INBOX is sent as an absent `mailbox` param, matching the links the web app builds for
  itself. It is launched as an `ACTION_VIEW` intent so an installed PWA or the user's browser handles
  it, with the session it already has; **never** an in-app WebView, which would share no session and
  would put an account-password field inside this app.
- **Reply threading (KyPost-Server #352).** Reply and Reply All send `replyToMessageId` and
  `replyToMailbox` (the row's id and folder) on `/api/mail/send` only, never on drafts or
  `/api/mail/send-pgp`; the fields are omitted when null, so an older relay sees the request it
  always did and sends unthreaded. The reference reaches Compose through `ReplyThreadHandoff`, a
  process-scoped map keyed by a random token on the Intent, because `ComposeActivity` is exported
  and a plain extra would let any app thread its prefilled message onto mail in this mailbox. It
  survives the lock in `CachedDraft.replyTo`. `MailOutcome.ReplyThreadingRefused` is one of the
  relay's four exact refusal sentences (`isReplyThreadingRefusal`), matched whole: other 502s on
  this endpoint can follow a delivery and quote SMTP text, so a word match could offer to re-send
  mail that already went out. On a refusal (sent before any delivery) Compose asks whether to send
  unthreaded and only re-sends on a yes. Any other failure, and every timeout, is reported and
  never re-sent. `dispatchSend` allows one send in flight (the composer's `ComposeSend.InFlight`,
  started or adopted after a rotation) and records the draft it sent, so the pickup and unthreaded
  dialogs re-send from each other's result rather than looping.
- `MailOutcome.ClientSideNeeded` is relay 409 carrying `clientSideNeeded` on `/api/mail/send` — a
  client-protected account asked the server to sign or encrypt and it refused rather than silently
  sending in the clear. `MailOutcome.RateLimited` is relay 429 with `Retry-After` (the per-device
  lockout); it is mapped in `RelayMailSource.execute`/`downloadAttachment` rather than `mapErrorCode`,
  which cannot see response headers.
- Encrypted send: `MailDraft.sign`/`encrypt`/`allowPickupFallback` reach `/api/mail/send` through
  `toSendWireDto()`, deliberately *not* the shared `toWireDto()` — `/api/mail/draft` ignores them,
  so the draft path stays flagless. `/api/mail/send` has **two** 409s, told apart by which JSON
  field is present, never by status or error prose: `clientSideNeeded` (the account's key is
  client-custody; no re-send helps, hand off to webmail) and `keylessRecipients` (nothing was
  delivered; re-sending the *same* draft with `allowPickupFallback = true` is safe and cannot
  duplicate). Only those two 409s and the 200 are JSON — every other status returns plain text, so
  no decoder runs over it. The recipient preflight is `POST /api/pgp/recipients/check`; it reads
  contacts only, so `hasKey: false` is a lower bound and must never be worded as a promise.
  (`/resolve` still 409s for every non-client-custody account, so it remains wrong for *this* path —
  but it is no longer wrong for the app as a whole; see the client-side send bullet below.) The pickup fallback
  stores the message's plaintext on the server for seven days, which is why its confirmation copy
  is fixed in `strings.xml` and is per-message — never a remembered preference.
- **Client-side encrypted send.** A client-custody account on an **enrolled** device encrypts and
  signs on the phone and posts ciphertext to `POST /api/mail/send-pgp`; it no longer falls back to
  webmail. `pgpComposeStateOf(hasIdentity, protection, deviceEnrolled, accountAddress)` is the whole
  rule, and its `clientSide` flag is what routes `ComposeActivity.sendEmail` to
  `ClientEncryptedSender` instead of `MailRepository.send`. Webmail remains the fallback for an
  unenrolled device, and for an enrolled one whose `accountAddress` is blank (no `From` could be
  built, so the relay would 403).
  - Recipient keys come from `POST /api/pgp/recipients/resolve` (`RecipientResolveClient`) — the
    endpoint the server-custody path must never call. Here 200, 409 and 413 are JSON while 400/500
    are plain text, which differs from `/check`.
  - The address split is `splitRecipientFields`, **not** `splitAddresses`: the latter dedupes across
    To/CC/BCC and would collapse a BCC recipient into the To header.
  - To+CC share delivery 0; each BCC gets its own ciphertext, so no BCC recipient's key id appears
    in a packet another recipient can read. Delivery 0 must stay first — index 0 failing is a hard
    502 while later failures only become a `warning`.
  - `OutgoingEnvelope` has no `bcc` field by construction, and the writer emits a fixed, closed
    header set — that is what structurally guarantees the relay's forbidden headers (`Received`,
    `Authentication-Results`, `Return-Path`, `Bcc`) can never appear.
  - The real subject rides inside the ciphertext as a protected header; the outer subject is always
    `OUTER_PLACEHOLDER_SUBJECT`, matching `pgpmail.OuterPlaceholderSubject`.
  - The Sent copy is encrypted to the public half of the **vault** key (`PgpEncryptor.ownPublicKey`),
    never to bootstrap's `publicKey`: a hostile server supplying "your" key would otherwise get a
    readable copy of every message sent.
  - A **locally pinned contact key outranks the relay**: `ClientEncryptedSender` fingerprints the
    resolved key and the pinned one itself (`PgpFingerprint.compute` over the key bytes, never the
    relay's `fingerprint` field), answers `KeyChanged` on a disagreement, and encrypts to the
    pinned bytes on a match. It is the write-path counterpart of `RoomLocalSignerKeys` on the read
    path; without it the outgoing key is only whatever the relay chose to hand back. `localKeys` is
    deliberately not defaulted.
  - Two rules make that pin **fail closed**, and both were once open. A pin that will not
    fingerprint is a REFUSAL, not an absence: `ContactMappers.toEntity` stores a relay key verbatim
    when `PgpFingerprint.compute` rejects it (unbound subkey, trailing ring) and keeps the previous
    fingerprint, so the lookup can hand back a pin that fingerprints to null — collapsing that into
    "never pinned" let a relay erase an in-person pin by serving a BROKEN key and then substitute
    any key it liked, where serving a merely different one would have been caught. And the lookup is
    `ContactDao.pinnedForEmail`, never `search`: `search` is the autocomplete query, name-ordered and
    capped at five rows, and the relay supplies the contact list, so same-address decoys sorting
    ahead of the pinned contact evicted the pin from its own lookup. `pinnedForEmail` is unbounded
    and unordered; the exact-address match stays in Kotlin so a substring cannot admit a lookalike.
  - `tier == "key_changed"` is a broken TOFU pin and must stay a distinct, louder outcome — never
    folded into "no key on file". There is **no** pickup fallback on this path and there must not be:
    the server-side one works by storing plaintext, which is what client custody exists to prevent.
  - `accountAddress` is bootstrap's `suggestedUserIDs[0]` and nothing else — the server derives it
    from the same expression `handleMailSendPGP` feeds to `resolveMailFrom`. Do not derive it from
    the public key's User ID or the self-contact. The whole list (account address plus verified
    send-as aliases) is `addresses` (`accountAddresses()`), which Reply All (`replyAllRecipients`) leaves out.
  - `ComposePgpController` caches the **bootstrap**, not the composed state: custody is fixed at key
    creation but enrollment can change mid-process, so it is re-probed on every `composeState()`.
  - Sign-only is impossible (the relay accepts `multipart/encrypted` only), so the two chips are
    coupled when `clientSide`.
- Inbox tabs come from the relay's `tabs`/`label` response fields. IMAP system keywords (`$…`,
  `\…`) are message state, never tabs: `KeywordTabs.isSystemKeyword` filters them in `buildTabs`
  and on both the write and read side of `KeywordSettings`. They stay on `Email.keywords`, where
  `isFlaggedPhishing` reads `$Phishing`.
- Inbox search (`MailRepository.search` → `GET /api/mail/search?q=&mailbox=&limit=`) searches the
  folder on screen, all fields. Results are never written to Room (they are a view of the folder,
  not its sync window), each row is stamped with the searched mailbox, and they replace the list only while their query and folder are still on
  screen (`applySearchResults`). A folder switch, a notification tap or editing the submitted text ends the search; a failed search shows the folder list. The query is
  kept out of the saved-state Bundle. `InboxSearchTest` covers the stale-result guards.
  Because a result has no Room row, opening one passes its To/Cc to the detail screen
  (`email_sent_to`/`email_cc`). They seed Reply All and are handed to `fetchBody`, which uses them
  when no row exists (`SearchResultReplyAllTest`).
- `showThemed()` (`ThemedDialog.kt`) shows a native AlertDialog through `showSecurely()` and then
  tints its native surface (shape and insets kept), title, message, buttons, list rows and fields in the active palette
  (STYLE_GUIDE.md §6). A dialog is its own window, so the Activity's theme walk never reaches it.
  `ThemedDialogsTest` names the dialogs that must use it. The message screen's eight actions use
  `@dimen/detail_action_size`: 35dp below a 360dp window, 40dp from it, 44dp from 400dp, so all
  eight are on screen at 320dp and 360dp (`EmailDetailActionRowTest` checks positions, since
  overflowing fixed-size buttons keep their size and are only clipped).
- "Move to folder" (`MoveToFolder.kt`, detail screen) offers INBOX, the relay's top-level folders
  and the Archive subfolders, minus the message's own folder (`moveTargets`), and runs
  `MailRepository.move`, so the local row goes only once the relay confirms the id.
- Long-pressing an inbox row starts selection mode (an AppCompat `ActionMode`: Archive, Move,
  Junk, Delete). Taps toggle rows, swipes are off, and a folder switch or search ends it. Bulk
  actions go through `MailRepository.mutateAll`, one relay call per source folder, with the same
  claim-before-queue guard as a single action (`beginRemovals`; session and account captured at
  the tap). That method
  applies rule 2 above to a batch: it drops only ids absent from `failed[]`, and only when
  `processed` equals their count. A shortfall `failed[]` does not explain (the relay stops early on
  a cancelled request) confirms none.
  A selection holds at most `MAX_ACTION_IDS` (500, the relay's per-request cap); `toggleSelected`
  is the only entry point and refuses the 501st row with a toast. Search results replacing the
  list end the selection, so a bulk action never covers rows the user can no longer see.
  Selected rows have their folder pinned when the action is tapped, and the optimistic removal
  matches (folder, id), so a Move answered after a folder switch cannot hide a same-id row in the
  folder now on screen (`aLateBulkMoveRemovesOnlyRowsFromTheirOwnFolder`).
- Inbox swipes and bulk actions are undoable: the rows are hidden at once, a 5 s Snackbar offers
  Undo, and the relay is asked nothing until the window closes. One bar covers everything held:
  a new action replaces the bar (`DISMISS_EVENT_CONSECUTIVE` commits nothing), and its Undo takes
  back every held action. The bar itself closes the window (`commitsOnDismiss`: timeout or
  swipe), because Android stretches its timeout for the accessibility "time to take action"
  setting and a separate timer would commit while Undo is still on screen. Only the bar on screen
  commits: a replaced bar can still time out after its replacement shows, and that dismissal is
  ignored (`onUndoBarDismissed`). `PendingRowActions`
  runs each held action exactly once, at that dismissal or at `onStop` (leaving the screen
  confirms it), or never once undone. A process killed in the foreground inside the window loses
  the action, so the mail stays where it was. The detail screen's actions finish the Activity and
  are not undoable. `InboxUndoTest` and `PendingRowActionsTest` cover this.
- The folder picker's Sent and Drafts entries never guess a mailbox name. Each tap lists the
  top-level folders (`GET /api/inbox/folders`, no parent) and opens the first whose leaf matches
  the server's own alias list (`SpecialFolder`, mirroring `special_folders.go`). A localized name
  with no alias match shows "No Sent folder", because the relay exposes no special-use flag.
- The inbox asks for `preview=1` (KyPost-Server #351): at most 200 characters of plain text the
  server flattened from a body it already holds, shown muted under the sender in
  `item_email.xml` as plain `TextView` text, never markup, with format characters (bidi
  overrides, zero-width, tags; whole code points) dropped (`previewText`). A delta "updated" row carries none and keeps
  its stored one; any other row takes what the server sent. It is never stored for a
  `pgpEncrypted` row, whatever the server sends, and `clearServerDecryptedBodies` clears an
  encrypted row's preview even without a cached body. An older server sends none and the row
  shows no preview; a body is never used as one. The preview is not passed to the detail
  screen: a summary must not be quoted or rendered as if it were the message.
- The inbox is fetched with `bodies=0`, so **an inbox row never carries a body** and the `emails`
  table is a cache of the messages actually opened, not a mirror of the window. `fetchBody` fills a
  blank one from `GET /api/mail/body` and writes it back. Two rules hold this together, both with
  tests named for them in `MailRepositoryTest`:
  - A blank body on a `pgpEncrypted` row is the client-protected shape, not a cache miss — fetching
    there turns it into `BODY_UNAVAILABLE` and drops the webmail handoff. Signed-but-not-encrypted
    mail is *not* `pgpEncrypted`, so it fetches and keeps the server's copy as the fallback for a
    signature this device cannot verify.
  - `reconcileFetchResult` preserves a cached body whenever the response carries none, on both write
    paths. The relay answers `"delta": since > 0`, so the daily self-heal arrives as a *snapshot*
    through `replaceFolderSnapshot`, whose `@Upsert` rewrites whole rows — without this it would
    blank every opened body once a day, per folder.
- Email bodies carry the relay's `bodyMode` (`html`/`plain`) through the Room cache and into
  `EmailDetailActivity`; plain bodies must be escaped into whitespace-preserving block markup for
  HTML fallback/quoting, while HTML bodies must not be detected by content when the server supplied
  a mode. The detail screen renders known plain bodies in a native wrapping `TextView`, so email
  reading never requires horizontal scrolling.
- Calendar invites (`mail/CalendarInvite.kt`, `CalendarHandoff.kt`). KyPost writes no calendar
  and syncs none (DAVx5 does that). The detail screen downloads the first listed `text/calendar`
  part (else `application/ics` / `.ics`) and parses it on the device with a strict RFC 5545
  subset parser — no ical4j. Over 256 KiB, over 50 VEVENTs, or any structural error refuses the
  whole invite; a refusal or throw only hides the card. Only a VEVENT's own properties count
  (a VALARM's DESCRIPTION does not); RECURRENCE-ID overrides are never the headline event; an invite with no series master
  (override-only, e.g. an Outlook single-occurrence update) does not parse and shows no card.
  Lines are unfolded as bytes before UTF-8 decoding; dates resolve STRICT; format characters
  (bidi, zero-width) are stripped from text and refused in addresses. The organizer is shown as
  its bare `mailto:` address, never CN, and the card says when it is not the From address — the
  sender writes both. A TZID over 128 chars, or one no IANA, last-2/3-segment or ICU Windows-name
  lookup resolves, is read as floating and the card says so. **Add**
  fires `ACTION_INSERT` on `Events.CONTENT_URI` (no calendar permission) and only on a tap;
  CANCEL and REPLY offer no Add. Under Hostile Location Protection every calendar handoff,
  including the "Create event from this email" overflow item (subject and body only, no date
  guessing, never the decrypted body or protected subject), is confirmed first. A "Create
  event" tap during the body fetch waits for it (`BodyFetchGate`) rather than going out
  subject-only. The card is
  only as reliable as the relay's listing: invites appear only when `hasAttachments` is true.
- RSVP (Accept/Maybe/Decline on the invite card) sends an RFC 5546 REPLY through
  `MailRepository.send` with `MailDraft.calendarReply` → `/api/mail/send` `calendarReply.ics`
  (KyPost-Server #354), addressed to the ORGANIZER.
  - `rsvpDraft` copies UID and SEQUENCE, restates RECURRENCE-ID without TZID (the REPLY has no
    VTIMEZONE), adds DTSTAMP, folds at 75 octets. An unreadable SEQUENCE or RECURRENCE-ID means
    no RSVP.
  - ATTENDEE is the bootstrap `suggestedUserIDs` address the invite lists, else the primary; an
    alias is also sent as `from`. No usable address means no RSVP.
  - **Always** unencrypted and unsigned (the relay 400s `calendarReply` beside either flag), so
    each RSVP is confirmed in a dialog that says so. The draft never sets `sign`/`encrypt`.
  - Buttons need the relay's `calendarMethod` (#353): an older relay ignores `calendarReply` and
    would send plain mail. Only a 200 carrying `"calendarReply": true` (#354) is an RSVP
    (`rsvpResult`). A 200 without it means the organizer got plain mail: the user is told to
    update the server, the RSVP is not marked sent, and nothing is retried.
  - A refusal shows the relay's reason; nothing else is sent instead. Only a definite refusal
    (`refusedBeforeSending`) re-arms the buttons; a timeout says "may have been sent".
  - `RsvpTracker` (process-wide, keyed on UID + RECURRENCE-ID + SEQUENCE) owns RSVP state;
    screens derive their buttons from its `phases` and a send never touches the Activity that
    started it, so a rotation can neither double-send nor miss the outcome. A raised SEQUENCE
    is answerable again. An unsure send stays locked across a rotation; a fresh open may retry.
    The confirm captures `ProcessState.generation()` and `MailRepository.currentAccount()`.
    `sendBoundRsvp` does no I/O once that session has ended, and `sendMail(draft, account)`
    refuses a replaced pairing from the same read that authenticates the request (the
    `MailAccount` shape of #155), so an old account's reply never reaches a new relay.
    `RsvpTracker.complete` drops a completion from an ended session (no state, no toast).
- `pgp/deliverReadOutcome` owns completed attachment arrays inside the worker until rendering
  accepts them. Cancellation across the dispatcher return, render rejection, or a rendering
  exception wipes unadopted bytes; successful adoption transfers cleanup to the detail Activity.
- `renderableBody`/`blockExternalResources` strip remote resources from **both** reader variants
  before anything reaches the WebView; "Show images" restores `<img src>` and nothing else. An
  `<iframe>` is dropped whole, because `srcdoc` carries an inline document no attribute strip
  reaches. `EmailDetailActivityTest` is the contract for that.
- A tapped http(s) link in a message never opens directly. `mail/LinkTarget.kt` parses it once with
  OkHttp's `HttpUrl`, which parses like a browser: userinfo is not the host, a backslash ends the
  authority, and IDNs come out as `xn--` punycode. The confirm dialog shows that host, and the
  re-serialized `HttpUrl` is what gets opened, so the confirmed host and the loaded page cannot
  differ. The dialog is palette-themed (`showThemed`), with the host and address in the bundled
  IBM Plex Mono. Separately, `blockExternalResources` outlines any anchor whose text reads as an
  address on a different host (`linkTextMismatch`; `www.` and subdomains of the shown host agree)
  and appends "⚠ real-host" after it. That is advisory: the confirm dialog is the guard. A
  `$Phishing`-flagged message adds a warning to the dialog. `mailto:`/`tel:` open as
  before, and every other scheme stays refused. `LinkTargetTest` covers the parsing.
- Decrypted reader variants share a sanitizer-enforced aggregate data-image allowance, covering
  literal data URLs and rewritten CIDs even after "Show images". The 128 KiB inline ceiling leaves
  larger parts available for attachment open/save under the separate 4 MiB attachment budget.
  `MemoryBudget` counts conservative retained/render image buffers and reserves at least 4 MiB
  read headroom; this is not a bound on general HTML parsing or WebView image decoding.
- Keyword tuning is managed in `KeywordSettingsActivity` and persists both hidden/visible state and
  the user-defined drag order used by Inbox tabs. Newly discovered keywords append to that order.
  Its RecyclerView owns theming its checkbox rows because the global theme walker deliberately
  skips RecyclerView children.
  The Inbox freshness label stays centered immediately below those tabs. Before the first
  successful refresh it reads "Not updated yet", so its row never appears empty and the first
  success does not shift the message list.
  Each inbox row shows `atUtc` in the device zone (`inboxRowDate`: time for today, date otherwise,
  blank if unparseable). The "No messages in {folder}" empty state shows only once that folder has
  refreshed successfully (`inboxEmptyVisible`): a loading or unreachable folder never reads as empty.
  A refresh that lands mail above the top row scrolls to it when the list is at the top;
  otherwise a "N new messages" pill (`inbox_new_mail` plurals, polite live region) over the list
  counts it and scrolls up on tap. Only a repaint of the folder and tab already painted counts,
  and a pending saved-position restore wins. `InboxNewMailTest` covers both branches.
- Theme selection is managed in `ThemesActivity` and uses the shared theme name list based on
  `theme.ts` palettes, led by `Busnes Light`/`Busnes Dark` from `busnes-color-theme-handoff.md`.
  `AppTheme.DEFAULT_THEME` (`Busnes Light`) is the only place the fallback name lives — the
  stored-name read, the unknown-name fallback and the missing-palette fallback all go through it.
  An install that never picked a theme moves from `Patina Ky` to `Busnes Light`; an explicit
  choice is kept, because `getStoredThemeName` only discards names `THEME_OPTIONS` no longer
  offers. Palette colors are opaque six-digit hex without exception: `blend()` returns
  `Color.rgb`, so alpha in `line` survives as a fully opaque near-black in
  `applyEmptyStateBackground`. `ThemePaletteTableTest` holds both rules.
- `SettingsActivity` is only a hub for existing settings surfaces: Security, Themes, Keywords,
  Pairing, PGP Key, Signature, and About. Keep settings logic in the destination screens rather
  than duplicating it in the hub; Signature's destination is `showSignatureDialog`.
- The signature (`MailSignature.kt`) is plain text only, at most 1000 characters, in its own
  private preferences file. It is account data: the pairing purge deletes the file, and so does
  a security wipe. It is a user-typed setting, not mail metadata, so Hostile Location Protection
  does not suppress it. Compose escapes it (`plainTextToHtml`) and puts it after an RFC 3676
  `-- ` delimiter, above any quote (`withSignature`). It goes on new messages, replies and
  forwards, but never above text another app shared in, which is the message itself. A
  signature-only body counts as content, so Back on an untouched composer prompts once.
  `ComposeSignatureTest` covers the escaping and the share exclusion.
- Primary navigation uses `bottom_nav_menu.xml` for both phone bottom navigation and the `w600dp`
  rail on Inbox, Compose, Contacts, and Settings. The item order is Inbox, Compose, Lock, Contacts,
  Settings; Lock is an action that either locks immediately or opens Security when app lock is
  disabled, not a selected destination. Keep the destination behavior in `AppNavigation.kt`. Primary
  destination switches reuse existing destination activities with `FLAG_ACTIVITY_REORDER_TO_FRONT`
  and use the 120ms card-slide animations in `res/anim/nav_card_*`; settings subpages and security
  handoff use normal platform transitions. A screen being left keeps its own item checked so that
  reordering it to the front later cannot reveal the destination it previously launched. Rail
  insets must clear both the status bar and top app
  bar; content top insets must clear both too, because edge-to-edge content otherwise starts under
  the custom ActionBar. Launcher artwork shown inside the app is clipped to the shared 14dp panel
  radius so its dark source-image corners do not clash with lighter themes. Inbox remains the
  selected primary destination for mail folders, but its
  displayed label must mirror the active folder so Junk/Trash/Archive do not leave Inbox highlighted
  by name.
- Unread counts are local-cache counts, not server totals: each keyword chip shows how many unread
  rows of the folder on screen carry it (`KeywordTabs.unreadCounts`, with a spelled-out
  `contentDescription`), and the folder picker shows `EmailDao.unreadCounts()` per folder as of the
  last cache read, Archive summing its subfolders (`unreadInFolderTree`). Counts are only ever
  re-read from Room, never adjusted by arithmetic: a refresh reads rows and counts in one
  transaction (`cachedEmailsAndUnread`), and a confirmed read, unread, swipe or bulk action
  (once its Undo window lets it go) re-reads them on the Inbox IO thread whatever folder is on
  screen (`recountUnread`); a detail-screen removal shows at the next refresh. Chip counts skip
  rows held for Undo, as the list does. A
  chip's keyword lives in its `tag`; its text carries the count, so never read the keyword from
  the text. Paged-in rows count too, and their read state only refreshes when paged again. No
  launcher badge.
- Keyword refresh is best-effort every 90 seconds while inbox UI is foregrounded (both connection modes).
- Background keyword staleness is accepted; app catches up on next foreground refresh.
- Contact sync (`contacts/` package) mirrors `push/`'s repository+coordinator+singleton-graph shape:
  `ContactSyncClient` (OkHttp, device-id/secret auth) pulls/pushes `/api/contacts/sync`,
  `ContactSyncRepository` applies the delta into Room, and `ContactCursorStore` persists a
  per-subscriber cursor in Room alongside the contact outbox so acknowledgement is atomic.
  A create is pushed under the UUID `queueCreate` minted, never a blank uid: the server stores an
  unknown uid as a create under that uid, so a push replayed after a lost reply, or a create
  followed by an edit or delete in the same outbox, lands on one contact. That uid is permanent,
  so nothing remaps it after sync. `ContactCreateIdempotencyTest` pins all three cases.
  The outbox holds one row per uid (`coalescedChange`): an update to an unsynced create stays a
  create with the new payload; a delete always replaces whatever was queued and is still sent,
  because the create may already be on the server from a push whose reply is in flight. Rows are
  replaced with new ids, never edited in place — a running sync acks by the ids it read, and
  in-place edits would be acked unsent. `ContactOutboxCoalesceTest` covers both races.
  Pushes go in batches under the server's caps (`pushBatches`: 500 changes, 900 KiB of change
  JSON against its 1 MiB body limit), each acked and advancing the cursor on its own. 400/413 is
  "this request is too big": the batch is halved, and a single change still refused stays queued
  while the rest go out. Once a reply says `tooOld`, the remaining batches keep the stale cursor
  (cheap `tooOld` replies with no lists) and one `since=0` pull ends the sync. So does any sync
  that starts at cursor zero, pushes queued or not: a `tooOld` sync that failed before its pull
  leaves only the reset cursor to say a snapshot is owed. Until that pull commits, pushes ack their
  changes but leave the stored cursor at zero, so a failed pull is retried next sync.
  `ContactPushBatchingTest` pins all five.
  A `since=0` pull is a snapshot: after tombstone GC the server can no longer list what it
  deleted, so `applyDelta(snapshot = true)` removes every Room contact absent from it except
  uids still in the outbox. `ContactFullResyncTest` covers both.
  **Per address, a key verified on this device is authoritative; a synced key never is.** The PGP
  QR flow's two saves (`queueCreate`/`queueUpdate` with `verifiedInPerson`) are the only writers of
  `recipient_pins` after `MIGRATION_12_13`, and each replaces the pins for that contact's addresses
  — re-scanning is how a pin changes. The migration itself seeds the table with exactly what the
  lookup before it trusted (`legacyPins`: every contact key per address, with its confirmation), so
  an upgrade never turns a trusted key into an untrusted one. Pins are keyed on the fingerprint of
  their own bytes, and a confirmation stays only with a key its stored fingerprint names, bytes
  included when rows merge; `authoritativeKeys` re-checks that on every read. `LegacyKeyMigrationTest`. `RoomLocalSignerKeys` (`authoritativeKeys`) returns ONLY the pins
  for a pinned address, so a contact key the server delivers, on a replacement contact or as an
  update, cannot satisfy `ClientEncryptedSender.applyPins` and the send is `KeyChanged`. Sync never
  writes the table, so removing or rewriting the contact does not touch the pin; a wipe (database
  file) or unpair (`purgeAccountScopedData`) clears it. An address with no pin keeps the earlier
  behaviour: the contact's key, whatever its origin. Server-side provenance (`pgpKeySource`,
  `pgpKeyVerified`) is not read: it is the relay's claim. `RecipientPinRetentionTest`.
  The one thing a synced copy can do to a pin is revoke it, recorded when a contact is saved
  (sync or local), never by a lookup: `withVerifiedRevocation` takes, from a
  synced copy of the SAME primary key, revocations of that primary or of any subkey the pin holds
  (matched by fingerprint), each verified against the pinned primary, adds only those signatures
  to the pin and saves it. Encryption already skips a revoked subkey of the pinned bytes. A
  revoked pin is still the address's pin — no fallback — so the reader gives `KEY_CHANGED` and the
  sender `RecipientKeyRevoked`, before the vault opens. That outcome is for pins only
  (`LocalSignerKey.pinned`), and `isPrimaryRevoked` verifies the revocation rather than trusting a
  packet: the synced fallback key and pins seeded by `MIGRATION_12_13` hold bytes no one checked,
  so a revocation packet already on a v12 key counts only if it verifies. Seeded pins take synced
  revocations like any other pin: pins are matched by address alone. `PinnedKeyRevocationTest`,
  `PinnedKeyRevocationMergeTest`, `RevocationTrustTest`,
  `LegacyKeyMigrationTest.aBackfilledPin_takesASyncedRevocationOfItsKey`.
  Entry point is the Contacts nav item and the settings hub; CardDAV (the doc's alternative sync
  surface) has no mobile client — it is web/OS-driven.
  The contacts list shows a sync banner from `ContactSyncRepository.observeSyncStatus`: "N changes
  waiting" counts contacts (not outbox rows) with queued changes; "Sync stuck" with Retry and the
  latest failure's first line appears once a queued change is over an hour old or
  `STUCK_AFTER_FAILURES` syncs in a row failed. `ContactSyncHealth` keeps that failure count in
  memory only, so a restart forgets it; the outbox age does not. `NotPaired` is not a failure.
  vCard export (`contacts/VCard.kt` writer, `VCardShare.kt`): one contact from the detail screen
  or all from the list, as 4.0 or 3.0, shared as `text/vcard` through
  `EphemeralAttachmentBytes` (never storage; its 60 s TTL applies to the share sheet too).
  Refused under Hostile Location Protection by the same `attachmentSaveOffered` rule as saving an
  attachment, because the receiving app can persist it. The writer escapes every text value and
  strips control characters from URLs and TYPE labels, so a field cannot inject a property;
  `VCardWriterTest` holds that. The server uid is not exported. `VCardShareTest`
  (instrumentation) reads each dialog choice back through the provider as a receiver would.
  vCard import (list overflow) opens the system picker (`ACTION_OPEN_DOCUMENT`, no storage
  permission) and treats the file as hostile: `readVCardImport` reads at most
  `MAX_VCARD_IMPORT_BYTES` (256 KiB), then `parseVCards` requires strict UTF-8, vCard 3.0/4.0, and
  balanced BEGIN/END, and refuses the whole file past `MAX_VCARD_IMPORT_CONTACTS` (200) or the
  server's 64 values per field. It reads only the writer's properties: UID, KEY, PHOTO, groups and
  encoded values are ignored, so a file can never pin a PGP key or pick a server uid. A preview
  (count, first ten names, skipped cards) is confirmed before `ContactSyncRepository.queueImport`
  queues every contact as an ordinary create in one transaction. It refuses while the outbox is
  non-empty, because the push is not batched yet and a larger one could pass the server's
  500-change cap. `VCardParserTest` holds the refusals and the writer round trip.
  Its strings are `contacts_vcard_import_*`; `contacts_import_*` belongs to the separate
  "Import from other accounts" consent dialog.
- **CP2's `TYPE` columns are integer codes, not labels.** `Email`/`Phone`/`StructuredPostal` `TYPE`
  is DATA2, and the free-text name belongs in the paired `LABEL` (DATA3) with `TYPE_CUSTOM`;
  `DeviceContactFieldCoding` owns both directions of that mapping for every field kind. A label
  written into DATA2 shows blank in the system Contacts app and round-trips back into Room as `"2"`.
  `updateRawContactForDto` pushes every field `createRawContactForDto` writes (structured name and
  phonetics, organization with title and department, notes, birthday, emails, phones, addresses,
  IMs, websites, relations, other events) through `DeviceContactUpdatePlan`; the IM, website,
  relation and event rows come from builders both paths share. It advances the link's
  `deviceUpdatedAtEpochMs` only when the batch actually landed — stamping it for a write that never
  happened tells the next merge the device is already current.
- **KyPost is the declared contacts sync adapter for its own account** (`res/xml/syncadapter.xml`:
  `com.android.contacts`, `supportsUploading`, not user-visible), so contacts apps can treat its
  raw contacts as editable. `KyPostContactSyncService` is a non-exported stub: SyncManager binds it
  from system_server, as AccountManager binds the authenticator, so neither enters the
  exported-components allowlist; a system-initiated pass does nothing, because the coordinator and
  worker own sync and its gates. The same service carries `android.provider.CONTACTS_STRUCTURE`
  (`res/xml/contacts.xml`): AOSP Contacts treats an account without an `EditSchema` as read-only
  and discards a schema that breaks any of its parser rules, which `ContactsStructureSchemaTest`
  mirrors. `KyPostContactAuthenticator.addAccount` answers with the existing account, or holds the
  caller's response in `PendingAccountSetup` and opens the Contacts screen in account-setup mode.
  Any app can make that request, so setup never enables on its own: it asks first
  (`contacts_account_setup_message`), even with contacts permission already granted; Enable runs
  the normal enable flow and answers with the account once it exists, while declining or leaving
  answers with a cancel. Setup progress (confirmed, permission request outstanding) is saved state
  of its own, so a recreate re-asks or resumes. The app-lock redirect keeps the request
  (MainActivity resumes the flow after unlock). Each request's token rides in the setup intent
  (`ContactsListActivity.setupIntent`), and a screen acts on and cancels only its own request, so
  closing a screen whose request a newer one displaced leaves the newer one waiting.
  `AccountSetupConsentTest`. `editProperties` answers
  an empty bundle. `ContactSyncAdapterDeclarationTest`, `ContactAccountFlowsTest`. Unverified on
  hardware: how stock Contacts apps render and edit these contacts with the schema.
- **A raw contact carries its contact uid in `RawContacts.SOURCE_ID`**, written in the same
  `applyBatch` as the insert. `device_contact_links` is a cache of that: `adoptLostLinks` runs
  before the pull and relinks every row of our account by SOURCE_ID, tombstones included and
  whether or not the uid is still in Room, so a death between insert and link write, or cleared
  app data, rebuilds the link instead of duplicating the contact. A phone edit made while the link
  was gone is then pulled, not overwritten; a phone delete is queued and purged, not replaced; a
  row whose contact left Room is removed (`DeviceContactDeleteTest`). The push repeats the
  live-row lookup before any create. Linked rows from before SOURCE_ID are backfilled.
  `DeviceContactSourceIdTest` (real CP2) pins it; `MIGRATION_13_14` indexes the link table's
  `rawContactId`.
- **The periodic `DeviceContactSyncWorker` is the only background path to the server**, so it runs
  `ContactSyncRepository.sync()` before `syncAll()` (`runContactSync`). A server failure is the
  `serverSync` stage and does not skip the local device pass; device edits queued by a pass reach
  the server on the next one. `refreshGroups` fails when the group refresh did not succeed — the
  repository reports that as an outcome, not a throw.
- **Device sync must not lose a change that lands while it runs, nor wake itself.** A
  `DeviceContactSyncCoordinator` request during a pass sets `rerun` and gets one more pass rather
  than being dropped; the request (`claimPass`) and the pass's decision to stop (`runAgainOrStop`)
  share one lock, so a request can never land between the pass's last check and its exit. A dirty raw contact is cleared only at the `VERSION` the pull read, so a later
  edit stays dirty. The foreign-import watermark is the scan's start time, not its end.
  `makeContactsVisible` writes only when `UNGROUPED_VISIBLE` is off: each write notifies the
  contacts observer, which used to trigger the next sync, which wrote again.
- **A backend group's lifetime is the device group's.** After a group refresh that succeeded,
  `reconcileGroups` deletes, as the sync adapter and only within our account, the device group of
  every link whose group the server no longer lists (`groupRemovals`), then drops the link. A failed
  refresh removes nothing, since the Room groups were not refreshed. Title matching can link two
  backend groups to one device row, so a row a live group still links to is kept and only the
  obsolete link goes. `DeviceGroupDeleteTest` covers that and the account-type scoping.
- **Device merges are three-way.** `device_contact_links.syncedJson` (`MIGRATION_15_16`) holds the
  `ContactDto` both sides agreed on after the last sync. It is written on create and by the push
  pass, per field: `DeviceContactUpdatePlan.nextBase` takes Room's value for each field the phone
  will then hold too and keeps the old base for the rest, including fields the push never
  writes (websites, IMs, relations, events) — never by the pull, which runs before the phone has
  the merge. With no old base it needs every field to agree. `DeviceContactMergeBaseTest`.
  `DeviceContactFieldMerge.againstBase` gives each field to the side that changed it since then,
  so a field emptied on either side stays empty. `same` compares as CP2 stores: null, blank and
  empty are equal because CP2 drops empty rows, and labels ignore case because CP2 reads Room's
  "home" back as "Home". With no base (links
  older than the column, or adopted by SOURCE_ID) or a change on both sides, the old two-way rule
  decides, and it cannot tell cleared from unset. In `DeviceContactUpdatePlan` a blank or empty
  value is a clear: rows are deleted and nothing is inserted.
- **Importing another account's contacts uploads them, so it is per-account opt-in.**
  `importNewDeviceContacts` reads only raw contacts whose `DeviceAccount` (type, name; both null
  for the phone's own storage) is in `DeviceContactSyncSettings.importAccounts()`, which is empty
  by default and stored under a key no earlier build wrote — installs that imported everything
  start with nothing chosen. Consent is bound to the pairing it was given under
  (`ContactSyncRepository.destination`: the relay's canonical origin and the subscriber id); any
  other pairing reads none. It is checked again for each contact just before it is queued, inside
  `whileConsented`, which shares a lock with `setImportAccounts`, so withdrawing consent stops a
  scan already running. Inside that lock the scan also checks that its session
  (`ProcessState.generation()`, captured at scan start) and its pairing destination are still
  current, and abandons the scan if not. The account purge's database step runs under the same
  lock and clears consent (`clearConsentDuring`): the purge advances the generation only at its
  end, so this is what stops an import from landing in the outbox the next pairing inherits. Adding an account rewinds the scan watermark so its existing contacts
  are seen; a scan moves the watermark to its own start time only if `consentRevision` is
  unchanged since it began, so a rewind made mid-scan survives it. The choice is the Contacts menu's "Import from other accounts…" dialog, whose copy
  says the contacts go to the user's KyPost server. `DeviceContactImportConsentTest`.
- **Deletes reach the phone through Room.** `syncAll`'s `removeDeletedContacts` stage removes the
  raw contact of every link whose Room contact is gone, so server tombstones, snapshot prunes and
  local deletes share one path. A device-side delete is queued and then hard-deleted as the sync
  adapter: CP2 keeps `DELETED=1` rows until their adapter purges them. `deleteDeviceRawContact`
  drops the link only after CP2 confirms, so a failed delete is retried. `DeviceContactDeleteTest`.
- **A CP2 row that is deleted and reinserted destroys every column the reinsert does not re-emit.**
  The Organization row is therefore rebuilt from all three of company, title and department, each
  the plan's value or else the snapshot's; title and department are also merged into Room by the
  device pull, so a value typed on the phone is not just kept but synced. Custom relation labels
  read back from `Relation.LABEL` rather than collapsing to "other". IM, website, relation and event
  rows are rebuilt in Room's encoding and then take back the phone's own columns Room has no slot
  for: TYPE and LABEL, and an IM's PROTOCOL and CUSTOM_PROTOCOL (`DeviceRawContactSnapshot.keptRows`,
  keyed by `keptRowKey`: kind, how Room names the row, value; duplicates in row order). So Home/Work,
  a built-in protocol such as Jabber, Brother and Other survive an append (`DeviceContactImTypeTest`). Still unfixed
  on the same shape: `JOB_DESCRIPTION`, `OFFICE_LOCATION`, `SYMBOL`, `PHONETIC_NAME` and
  `StructuredPostal`'s `POBOX`/`NEIGHBORHOOD` are not in the snapshot at all, so every replace drops
  them. Widen the snapshot before adding another replaced group.
- **Writing a raw contact into CP2 is not the same as the user seeing it.** A raw contact that
  belongs to no group is hidden unless its account's `ContactsContract.Settings` row sets
  `UNGROUPED_VISIBLE = 1`; grouped contacts are exempt because `DeviceGroupLinker` sets
  `GROUP_VISIBLE`. Skipping it does not fail a write, log an error, or fail any test that only
  reads back `RawContacts` — it just presents an empty address book. `DeviceContactAccount
  .makeContactsVisible` owns the opt-in and `DeviceContactRepository.syncAll`'s
  `ensureAccountVisible` stage runs it on every sync, not only at enable time, so installs that
  predate it repair themselves. Assert visibility through `Contacts.IN_VISIBLE_GROUP`, never
  through the presence of the row.
- Room (`androidx.room`, `data/AppDatabase`) is a deliberate, user-requested exception to "do not
  add new dependencies unless they reduce overall code size/complexity" below — it's the local email
  and contacts cache. KSP (Room's annotation processor) needs
  `android.disallowKotlinSourceSets=false` in `gradle.properties` to coexist with AGP's built-in
  Kotlin compilation (this project applies no separate `org.jetbrains.kotlin.android` plugin) — a
  known KSP/AGP-9 interaction (google/ksp#2729), not a general opt-out of that migration.
- **Comments say what the code cannot; commits say what it used to be.** A third of this
  module's non-blank lines are comments, and most of them follow the shape "X used to be Y, which
  was wrong because Z". That is a commit message — `git log` already holds it, permanently, attached
  to the diff that made the change — and in source it goes stale silently. It did: this file spent a
  release telling every reader `kypost_mail.db` was plaintext, one commit after it was encrypted.
  Keep in-source comments for what the code genuinely cannot state: a wire-format contract
  (`Sec1Point.kt`), a packet-ordering requirement (`PgpEncryptor`), a non-obvious ordering
  constraint. **Where a comment asserts a security property, write the test instead** — every
  "this cannot happen" in the at-rest path that was checked in this review turned out to be able to
  happen.
- **`kypost_mail.db` IS encrypted at rest, with SQLCipher.** Room is built through
  `SupportOpenHelperFactory` keyed from `security/DatabaseKey.kt`: 32 random bytes, base64, held in
  a Keystore-backed `EncryptedSharedPreferences` file (`db_key_secure`) and never derived from the
  app-lock PIN — the database has to open in processes where no PIN has been entered (an FCM
  delivery, a WorkManager sync). The threat this closes is **offline** reading of the file: root, an
  unlocked bootloader, a forensic image. It is explicitly not a defence against a live, rooted,
  running device.
  - Existing plaintext databases are converted in place by `data/DatabaseMigration.kt`
    (`sqlcipher_export` into a temp file, verified under the new key, then one atomic `rename(2)`).
    The conversion must never delete the original before the rename — a process death in that
    window destroyed the mailbox, and `pending_contact_changes` exists nowhere else.
    `recoverInterrupted` salvages temp files left by builds that did.
  - `DataGraph` **checks** `encryptIfNeeded`'s return and throws `DatabaseUnavailableException`
    rather than handing a plaintext file to SQLCipher, which surfaced as `SQLITE_NOTADB` on a
    background thread on every launch with the cause nowhere near the symptom.
  - `SecurityWipe` has a `databaseKey` step: an encrypted database is only as gone as its key.
  - The app-lock apparatus (PIN, lockout ladder, wipe threshold, `AppLockStore`'s tripwire) still
    defends the **UI** and is a separate control from this one. Hostile Location Protection
    (`security/HostileLocationSettings` → `data/DataGraph` builds Room in-memory) remains the
    stronger mode for users whose threat model includes a live rooted device, at the cost of all
    offline access — under it there is no file at all.
  - SQLCipher was previously rejected here as a large native dependency. That call was reversed on
    2026-08-18 because the alternative was "your mail is in the clear on disk unless you find and
    enable an off-by-default setting", which is the wrong default for a confidential mail client.
    The AAR ships `libsqlcipher.so` and loads it nowhere, hence `sqlCipherLoaded` in
    `DatabaseMigration.kt`. **If this decision is ever revisited again, update this bullet and
    `AppLockStore.tripwire`'s KDoc in the same commit** — the previous change did not, and this
    file spent a release telling every reader the database was plaintext.
- Every text field asks the keyboard not to learn what is typed (`IME_FLAG_NO_PERSONALIZED_LEARNING`).
  XML fields declare `flagNoPersonalizedLearning` in `imeOptions`, and fields built in code call
  `noPersonalizedLearning()`. `KeyboardPrivacyTest` fails on any new field without it. Keyboards
  may ignore the flag. The compose body is out of reach: `RichHtmlEditorWebView` is a `final`
  library WebView whose `onCreateInputConnection` cannot be overridden.
- Compose's address-book and Send action icons use the active palette's `inkStrong` color.
- Send needs a recipient and a body. A blank subject is legal (the relay doesn't require one), so
  compose asks "Send without a subject?" instead of refusing (`sendReadiness`).
  Every path to the relay (menu, that confirmation, the editor's export callback, the client send
  and the pickup-fallback re-send) asks one gate, `custodyPermitsSend`, at the moment it would
  send: custody can resolve while a prompt is open. Send stays disabled until custody is known.
  `ComposePgpController.composeState()` returns null when it couldn't check (unpaired or bootstrap
  failed); that is not "no identity" and must never be mapped to all-false flags, or a
  client-custody account sends in the clear. Compose keeps custody unknown, shows a Retry
  Snackbar, and retries on resume or a Send tap (`resolveCustody`).
  `ComposeCustodyGuardTest` covers the confirmation path and a failed bootstrap.
  On the client-encrypted path the protected `Subject` header is always written, empty if need
  be, and `PgpMimeReader` reads a present-but-blank header as an empty subject. An absent header
  still means "none", so the outer placeholder never stands in for a subject the sender left
  blank.
- STYLE_GUIDE.md §7 gaps are closed: `EmailDetailActivity`'s WebView renders the body in the real
  IBM Plex Mono font via a base64-inlined `@font-face` (`AppTheme.ibmPlexMonoFontFaceCss`, backed
  by `assets/fonts/IBMPlexMono-Regular.ttf`) rather than a `file://` base URL, to avoid granting
  untrusted email HTML `file://` origin access. `AppTheme.applyStatusBadgeTheme` is the
  active/inactive status-badge+dot component (mirrors iOS `StatusBadgeView`/Linux `StatusBadge`);
  its only current consumer is `ContactAdapter`, keyed off `ContactEntity.pgpKey` presence — the
  address-book picker (`RecipientRowAdapter`/`RecipientCandidate`) does not project `pgpKey` and
  wasn't wired up. `AppTheme.animateChipColorTransition` (120ms, `FastOutSlowIn`) is the shared
  motion helper; only `applySuccessChipTheme`'s address-book "added" transition uses it
  (`animate = true` param, default `false`) — `applyPillChipTheme`'s checked/unchecked toggle was
  deliberately left un-animated (Chip's own state machine already transitions it; STYLE_GUIDE.md §7
  doesn't require a full pass).

# Work Guidance

- Keep network off the main thread.
- Keep lifecycle-safe polling: start in foreground lifecycle, stop on background lifecycle.
- Prefer immutable model updates for inbox list and keyword tabs.
- Do not add new dependencies unless they reduce overall code size/complexity.

# Verification

- Add or update unit tests in `app/src/test/` for tab computation and filtering logic.
- Add or update unit tests for deep-link parsing, pairing validation, native registration endpoint resolution, payload parsing, and native registration request mapping.
- `SecurePairingStore` (EncryptedSharedPreferences-backed) requires a real Android Keystore and is covered by an instrumentation test in `app/src/androidTest/` instead of a JVM unit test.
- Certificate-chain pinning has a JVM test (`push/TlsChainPinningTest`) asserting every captured pin is registered for the host and that an empty pin set is refused. A pinning change that only tests the state machine (pinned / never-paired / lost) does not cover the lifecycle event that actually happens — renewal — so add the rotation case too.
- The pin cache has JVM tests (`push/PinnedCallFactoryProviderTest`, `push/PinnedOrFallbackCallFactoryTest`): a pin replaced while a caller waits must not be built from the stale read, and a request for an unpinned host must be refused. Attachment saves have `security/AttachmentDownloadCleanupTest` in `app/src/androidTest/` (real MediaStore): a failed write leaves no row in Downloads and keeps its ledger entry.
- Interrupted-PIN-change recovery is covered by `push/PinChangeSecretRecoveryTest` in `app/src/androidTest/` (real Keystore required): it kills the change at each step and asserts the device secret is still readable, and that a genuinely stranded secret is reported by `deviceSecretIsStranded`.
- Validate manifest registration when adding activities or permissions.
- Room DAO behavior (e.g. `EmailDao.replaceFolderSnapshot`, contact upsert/delete) is covered by
  instrumentation tests in `app/src/androidTest/` using `Room.inMemoryDatabaseBuilder` (no
  Robolectric dependency in this project — don't add one for this).
- The email `bodyMode` column is additive and requires `MIGRATION_10_11` plus a migration test when
  the schema contract changes again. `MIGRATION_11_12` re-keys `emails` on (folder, messageId);
  SQLite cannot alter a primary key, so it rebuilds the table and copies rows rather than dropping
  the cache. `MIGRATION_14_15` adds `inWindow` (default 1: every earlier row came from the window). `EmailDaoFolderScopeTest` is the authority on that key against real SQL — the JVM fake
  in `MailRepositoryTest` mirrors it, and a fake keyed on the id alone reproduces the very bug the
  key exists to prevent.
- The mail failure contract has JVM regression tests in `MailRepositoryTest`: a failed reconcile
  must leave the cursor where it was, an action returned in `failed[]` must not mutate Room, and
  `markRead` must not mark a row read the server rejected. Adding a mail sync or action path
  without one of these is how the contract rots back.
- Add or update unit tests for contact-sync reconciliation/delta-merge logic and relay response
  mapping (HTTP status → `MailOutcome`/`ContactSyncOutcome`, and the `to`/`cc`/`bcc`
  comma-string-not-array request shape) under `app/src/test/`.
- Keep the PGP banner rule and the webmail URL as pure functions (`pgp/PgpMessageState.kt`,
  `pgp/WebmailDeepLink.kt`) with JVM unit tests, rather than deriving either inside an Activity —
  the Activity only picks views. Room schema changes need a matching `MigrationTest` case in
  `app/src/androidTest/`; migrations may set SQLite column defaults without the entity declaring
  `@ColumnInfo(defaultValue=…)`, since Room only validates a default when the entity side has one.
- `pgp/SecretKeyRingMergeTest` proves current-first signing, retired-key decryption, same-primary
  subkey retention, idempotence, invalid-input refusal, and every enrollment limit on the JVM.

# Child DOX Index

- No child AGENTS.md files.

## Product icon

Notification small icons use `drawable/ic_notification`, a white envelope with a transparent
flap cutout and background. Android renders the alpha mask; an opaque launcher background
loses its artwork when tinted. Use this drawable for mail, redacted mail, and MFA notifications.

App/launcher assets use the Busnes.app-site Systems stamp family. Regenerate platform sizes from the matching master in `../Busnes.app-site`; preserve resource names and adaptive foreground safe margins. The adaptive background (`ic_launcher_background.xml`) is `#182326`, matching the badge
baked into `ic_launcher_foreground` so the badge edge disappears and the launcher shows one
charcoal field behind the envelope — a cream background left a ring inside the launcher's
mask, since the foreground is a 64dp badge on a transparent 108dp canvas. Changing it is
launcher-only: the two adaptive-icon XMLs are its only referents, and the in-app artwork
(`applyKyPostTopBar`, `activity_tip.xml`) draws `ic_launcher_foreground` directly. At
`minSdk 31` those XMLs in `mipmap-anydpi` resolve ahead of the per-density
`ic_launcher*.webp`, which still carry the older cream-ringed composite.
