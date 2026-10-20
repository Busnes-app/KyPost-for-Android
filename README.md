# KyPost for Android

KyPost is an Android email client for a self-hosted KyPost server. Read and send mail,
organize keyword-based inbox tabs, exchange PGP keys and synchronize contacts in both
directions. Pairing creates per-device credentials; the phone does not need the mailbox’s
IMAP/SMTP password. Play/GitHub builds receive FCM notifications; the Google-free F-Droid
variant uses the server’s pull path.

## Install and pair

Requires Android 12+ with a secure screen lock and a reachable **KyPost server over HTTPS**.
Install and configure [KyPost Server](https://github.com/Busnes-app/KyPost-Server) first,
including the user’s IMAP/SMTP mailbox (or a separately qualified native mailbox). This
client does not connect directly to an email provider.

1. Use a signed APK from an actually published [GitHub release](https://github.com/Busnes-app/KyPost-for-Android/releases), or your approved Play listing. The GitHub v0.4.2 release is still a draft as of 2026-10-20; a draft is not a public download. F-Droid publication is pending. For local evaluation, use the debug build below.
2. In KyPost’s web security/device settings, create a new pairing QR/link for your everyday account. Open it in the intended KyPost channel on the phone and confirm the displayed server.
3. Grant notification permission if wanted, then verify inbox access and a controlled send/reply. A scanned QR is not a successful pairing until registration returns success.
4. Device sign-on through KyAuth currently supports the pinned **Play** package only. GitHub and F-Droid variants hide/refuse it; use QR/link pairing there.

Keep existing pairing and PGP recovery material when updating the same channel. Changing
channel/package is a separate install and requires pairing again. See [Channels](#channels).

## Features

- **Mail**: The paired KyPost relay proxies mail; the app stores no mail credentials on the device.
- **Keyword tabs**: Inbox tabs come from server tab and label fields. Tune the tabs in the Keywords screen.
- **Compose**: The To, Cc, and Bcc fields complete recipients from local contacts. An address-book picker adds recipients directly.
- **Contacts**: A two-way contact sync runs against a self-hosted KyPost server. Open it from the Inbox overflow menu. Contacts held by other accounts on the phone (Google, SIM, …) are uploaded to your server only from accounts you pick under **Import from other accounts**; none are picked by default.
- **PGP**: One screen shows your own PGP public-key QR code and scans another person's, saving that key onto an existing contact. The app also encrypts outgoing mail to a recipient's key, and decrypts client-custody mail on the device once it holds a sealed key envelope — see **Device enrollment** in [SECURITY.md](SECURITY.md). Without that envelope, encrypted mail hands off to webmail instead.
- **Calendar invites**: A message carrying an invite shows a card with its time in your zone, place, organizer address and method. **Add to calendar** hands the event to your calendar app, which then keeps its own copy; KyPost never adds an event by itself. **Accept / Maybe / Decline** sends an RSVP to the organizer; RSVPs are always sent **unencrypted**, and the app says so before each one. KyPost does not sync calendars — use DAVx5 for that.
- **MFA push approval**: Push notifications approve or deny KyPost account logins. An in-app screen does the same when OEM background limits block the action notification.
- **Themes**: The app shares theme presets with the KyPost web app. The default, **Follow system**, switches between **Busnes Light** and its charcoal counterpart **Busnes Dark** with the system dark mode, and the 15 older presets are still offered. Select a theme in the Themes screen.
- **Push notifications**: The app shows system notifications and keeps an in-app notification history for new mail. Each user selects a delivery mode (`push` or `pull`).

## Push notification pairing

- The app pairs the device from a desktop deep link or QR code:
  `kypost://native-pair?sub=<subscriberId>&srv=<serverUrl>&reg=<registrationUrl>&pt=<pairingToken>`
- The link must use `https` for both `srv` and `reg`, and `reg` must be the same origin as `srv`. The app refuses the link otherwise, because `reg` is where the device secret is minted and the confirmation dialog shows the user `srv`.
- **Authentication is per device, not per account.** Registration exchanges the one-time `pairingToken` for a `deviceId` and a `deviceSecret` minted by the server. Every later request sends them as the `X-Kypost-Device-Id` and `X-Kypost-Device-Secret` headers. There is no `hash` parameter and no account-wide subscriber HMAC; the server no longer accepts them. Revoke a single device from the server's Security page.
- The app stores the pairing proof material in a Keystore-backed `EncryptedSharedPreferences` file: the subscriber id, the server URL, the registration URL, the pairing token, the device id, and the device secret. The app does not store this material in the plaintext DataStore that holds the notification history and the sync status.
- The app registers the FCM token against the native registration endpoint of the backend. It uses `reg` from the QR code. If `reg` is absent, it derives `{srv}/api/notifications/native/register`. The app repeats this call on pair and on each token refresh. Each successful registration mints a **new** device secret and invalidates the previous one.
- The app marks the device as paired only after the registration call succeeds (`ok:true` or `synced:true`). A QR code scan alone does not pair the device.
- The app handles these FCM data payload keys: `messageId`, `senderName`, `emailSubject`, and `Keywords`.
- The app shows system notifications and keeps an in-app notification history.
- Each user selects a **delivery mode** (`push` or `pull`) on the web Notifications page. In `pull` mode the server sends nothing to FCM. The app polls the server directly.

## Pull mode (FCM and relay bypass)

- The native registration response also returns `deliveryMode` (`push` or `pull`) and `pullEndpoint`. The app stores both values. If `pullEndpoint` is absent, the app derives `{srv}/api/notifications/native/pull`.
- In `pull` mode the app polls `GET {pullEndpoint}?after=<cursor>`. The cursor is the only query parameter. Authentication is the `X-Kypost-Device-Id` and `X-Kypost-Device-Secret` headers, never a query parameter — credentials in a URL end up in server access logs and browser history. The request uses no session and no bearer token. FCM stays registered but is not the source of truth.
- The app renders each returned notification through the dispatcher that handles an FCM data message. The tap behavior is therefore identical.
- The strictly increasing `seq` value removes duplicates. The app advances a durable per-subscriber `lastCursor` to `max(lastCursor, response.cursor)`. It advances the cursor only after it hands off the notifications, so a crash causes a re-fetch instead of a lost notification.
- The `deliveryMode` value in the register response and in the pull response is authoritative. A change to `push` on the web stops the polling. A change to `pull` starts the polling again. The app reads the value again on every app foreground.
- **Cadence tradeoff**: pull mode has no push message to wake the app. Background delivery uses WorkManager periodic work at the platform minimum of 15 minutes. The app also pulls immediately on app foreground and after each pairing. Near real-time background delivery needs a foreground service with a short poll loop and a persistent notification. This is not the default by design. The app backs off after `400`, `401`, and `503` responses and after network errors, so it does not loop tightly.

## Firebase setup

Firebase is required for the `play` and `github` build variants only:

1. Register `org.kysecurity.mail` and/or `org.kysecurity.mail.github` in your Firebase project for the variants you intend to build.
2. Download `google-services.json` with the matching client entries and place it at `app/google-services.json` (gitignored).
3. Enable FCM and configure the paired backend’s native push delivery.

The `fdroid` variant contains no Google/Firebase code and disables its Google Services
processing tasks. It needs neither a Firebase app entry nor `google-services.json`; its
pull-based operation does not qualify FCM delivery. On Play/GitHub, a missing matching
client fails `process<Variant>GoogleServices` rather than silently disabling push.

## Notification permission behavior (Android 13 and later)

- The app requests `POST_NOTIFICATIONS` at launch.
- If the user denies the permission, the app still parses each delivered push payload and saves it to the in-app history. The app does not show system notifications.

## Pairing from a desktop QR code

1. The desktop web app shows a QR code with the deep link. The link contains `sub`, `srv`, `pt`, and optionally `reg`.
2. In the Push Notifications screen, tap **Scan QR Code**. You can also open the deep link directly, because the app is a handler for `kypost://native-pair`.
3. The app validates the required parameters (`sub`, `srv`, `pt`), checks that `srv` and any `reg` are `https` and the same origin, and resolves the registration endpoint.
4. The app shows a confirmation dialog naming the server host, then calls the native registration endpoint with the FCM token. The app marks the device as paired only on success, and stores the `deviceId` and `deviceSecret` the response returns.
5. On each later FCM token refresh, the app repeats the same registration call with the stored pairing.

## Troubleshooting checklist

- Make sure the deep link scheme and host are exactly `kypost://native-pair`. The app no longer supports the legacy `novu-pair` host or the old `llamalabels://` scheme.
- Make sure the required query parameters exist: `sub`, `srv`, and `pt`. A link that still carries `hash` comes from an outdated server; the app ignores the parameter and the server no longer accepts it.
- Make sure the device can reach the resolved registration endpoint (`reg`, or `{srv}/api/notifications/native/register`).
- For Play/GitHub builds, make sure the Firebase project has a client for the package you built. F-Droid has no Firebase dependency; check its server/pull configuration instead.
- If the registration fails with `400`, the request was malformed or missed a field.
- If the registration fails with `401`, the pairing token (`pt`) is invalid or expired. Scan a new QR code.
- If the registration fails with `503`, the backend has no `PAIRING_SECRET` configuration. The app cannot retry around this error.
- If Android 13 or later shows no notification, make sure the user granted the notification permission.

## Privacy and data collection

The Google/Firebase dependency details below apply to Play/GitHub variants. F-Droid omits those libraries; all variants still send pairing credentials to the chosen server.

- The app does not use the Android advertising ID (AAID). No source file calls `AdvertisingIdClient`, and no merged manifest declares `com.google.android.gms.permission.AD_ID`.
- No advertising or attribution library is in the dependency graph. The resolved Google Play services artifacts are `play-services-base`, `-basement`, `-cloud-messaging`, `-code-scanner`, `-stats`, and `-tasks`. Neither `play-services-ads-identifier` nor `play-services-appset` is present.
- Firebase Analytics is not included. The build pulls `firebase-messaging`, `firebase-installations`, and their support artifacts. FCM identifies the device with the Firebase installation id, not with an advertising id.
- The device identifiers the app does hold are the FCM token and the pairing material described in **Push notification pairing**. Both go only to the paired KyPost relay.

## Build and test

Clone this repository, install Android SDK platform 36.1/build tools as required by the
Gradle configuration, and set `ANDROID_HOME` or a gitignored `local.properties` SDK path.
Use the checked-in wrapper; its daemon criteria select JDK 21. Play/GitHub builds also
need the matching Firebase configuration above. For a local build without Firebase:

```sh
./gradlew assembleFdroidDebug
# With a disposable Android 12+ device connected and USB debugging enabled:
./gradlew installFdroidDebug
```

These are development APKs, not signed distribution releases. Use a separate test install
and keep existing release-channel data. The Play-specific checks below need Firebase.

```sh
./gradlew testPlayDebugUnitTest
```

```sh
./gradlew assemblePlayDebug
```

Instrumented tests need a connected device or emulator, **with a secure lock screen set**. The Keystore-backed enrollment vault refuses to create a key without one by design, so on a bare emulator the vault suites fail as though the code were broken. CI sets a PIN first; see the `instrumented` job in `.github/workflows/ci.yml`.

```sh
./gradlew connectedPlayDebugAndroidTest
```

The opt-in `NativeMailboxRoundtripTest` requires a dedicated disposable emulator and
KyPost-Server's `TestNativeOutboundAPIActualTLSAndPGP/device-android` fixture. Build and
install both Play debug APKs, then set `KYPOST_NATIVE_ANDROID_TEST_SERIAL` while running
that server case; see [server qualification instructions](https://github.com/Busnes-app/KyPost-Server/blob/main/docs/TURNKEY_MAIL_PHASE1.md#android-native-mail-runtime-qualification).
It verifies real pinned HTTPS registration, encrypted pairing preferences, native mail
IDs through Room, body/label/attachment/read-state sync and ordinary send/Sent. It clears
pairing state on the test install. Ordinary instrumentation skips it without fixture
arguments; use only disposable data. PGP enrollment, UI flows, physical-device testing
and live provider receipt remain separate checks.

### Release builds

Use channel-specific tasks: `assembleGithubRelease`, `bundlePlayRelease`, or
`assembleFdroidRelease`. Release packaging **fails without signing material** by design.
Keep only the keystore path and alias in a gitignored `keystore.properties`:

```properties
storeFile=/absolute/path/to/your.jks
keyAlias=your-key-alias
```

Supply passwords through `KYPOST_STORE_PASSWORD` and `KYPOST_KEY_PASSWORD`, with
`KYPOST_KEYSTORE`/`KYPOST_KEY_ALIAS` available as environment overrides. Use a private
secret mechanism rather than typing values into history. `checkSigningSecretsAreNotInTheTree`
rejects cleartext signing passwords in `keystore.properties`; see
[keystore.properties.example](keystore.properties.example). Preserve the release signer
for future updates. Debug keys and CI’s throwaway signer are not distribution keys.

- CI's `release-build` job generates a throwaway key per run, so every PR still verifies the R8 configuration and `lintVitalRelease` without the real key ever being reachable from a `pull_request` trigger.
- Published builds come from `.github/workflows/release.yml` on a `v*` tag. It reads the real key from the protected `release` environment, checks the tag against `versionName`, and refuses to publish unless `apksigner` reports the expected `RELEASE_KEY_SHA256` signer. Never build a release for distribution from a workstation.

### Channels

KyPost for Android ships from three channels, and each is a separate app on your device:

| Channel | Package | Signed by |
| --- | --- | --- |
| Google Play | `org.kysecurity.mail` | Google, under Play App Signing |
| GitHub Releases | `org.kysecurity.mail.github` | our upload key |
| F-Droid | `org.kysecurity.mail.fdroid` | not yet live — the flavor builds from source with no Google code, but it is not yet submitted |

Android identifies an app by its package **and** its signature, so a build from one
channel can never update a build from another. Distinct packages make that explicit
rather than presenting it as a corrupt update: you can run more than one at a time,
and each keeps its own mail, contacts and keys.

With more than one channel installed side by side, a `kypost://native-pair` link opens
Android's app chooser instead of a single app — pick the copy you actually mean to pair,
since pairing the wrong one is silent and does not fail.

**Upgrading a sideloaded install from before this change:** the GitHub APK's package changed
from `org.kysecurity.mail` to `org.kysecurity.mail.github`. Android will not install it
over the old one. Uninstall the old app first — **this erases its local data, so re-pair
with your server afterwards.** This is a one-time break; GitHub-channel updates after
this one install normally.

## Test coverage

- Deep-link parser tests (`NativePairingDeepLinkParserTest`)
- Pairing validation tests (`PairingValidatorTest`)
- Native registration endpoint resolution tests (`NativeRegistrationEndpointResolverTest`)
- Payload parser tests (`messageId`, `senderName`, `emailSubject`, `Keywords`)
- Native registration request mapper tests (`NativeRegistrationRequestMapperTest`)
- Secure pairing store round-trip and encryption tests (`SecurePairingStoreTest`, instrumented)
