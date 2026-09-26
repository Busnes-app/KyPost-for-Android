# KyPost for Android

KyPost is an Android email client backed by a self-hosted KyPost relay. It shows keyword-based inbox tabs and synchronizes contacts in both directions. Native-push pairing authenticates relay access and contact sync. The app gets push notifications through native backend pairing and FCM. The client does not use Novu. The backend owns any Novu integration behind its own registration endpoint.

## Features

- **Mail**: The paired KyPost relay proxies mail; the app stores no mail credentials on the device.
- **Keyword tabs**: Inbox tabs come from server tab and label fields. Tune the tabs in the Keywords screen.
- **Compose**: The To, Cc, and Bcc fields complete recipients from local contacts. An address-book picker adds recipients directly.
- **Contacts**: A two-way contact sync runs against a self-hosted KyPost server. Open it from the Inbox overflow menu.
- **PGP**: One screen shows your own PGP public-key QR code and scans another person's, saving that key onto an existing contact. The app also encrypts outgoing mail to a recipient's key, and decrypts client-custody mail on the device once it holds a sealed key envelope — see **Device enrollment** in [SECURITY.md](SECURITY.md). Without that envelope, encrypted mail hands off to webmail instead.
- **MFA push approval**: Push notifications approve or deny KyPost account logins. An in-app screen does the same when OEM background limits block the action notification.
- **Themes**: The app shares theme presets with the KyPost web app. The default theme is **Busnes Light**; **Busnes Dark** is its charcoal counterpart, and the 15 older presets are still offered. Select a theme in the Themes screen.
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

1. In the same Firebase project, create or update a Firebase Android app for **each** of the
   three application ids: `org.kysecurity.mail`, `org.kysecurity.mail.github`, and
   `org.kysecurity.mail.fdroid`. The google-services plugin fails any variant whose applicationId
   it cannot find a client for, so a `google-services.json` missing one silently means that
   channel's build breaks at `process<Variant>GoogleServices`.
2. Download the merged `google-services.json` (it holds all three clients once they exist).
3. Put the file at `app/google-services.json`.
4. Enable FCM in the Firebase project settings.

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
- Make sure the Firebase project has a registered app for whichever of the three packages you built (`org.kysecurity.mail`, `.github`, or `.fdroid`).
- If the registration fails with `400`, the request was malformed or missed a field.
- If the registration fails with `401`, the pairing token (`pt`) is invalid or expired. Scan a new QR code.
- If the registration fails with `503`, the backend has no `PAIRING_SECRET` configuration. The app cannot retry around this error.
- If Android 13 or later shows no notification, make sure the user granted the notification permission.

## Privacy and data collection

- The app does not use the Android advertising ID (AAID). No source file calls `AdvertisingIdClient`, and no merged manifest declares `com.google.android.gms.permission.AD_ID`.
- No advertising or attribution library is in the dependency graph. The resolved Google Play services artifacts are `play-services-base`, `-basement`, `-cloud-messaging`, `-code-scanner`, `-stats`, and `-tasks`. Neither `play-services-ads-identifier` nor `play-services-appset` is present.
- Firebase Analytics is not included. The build pulls `firebase-messaging`, `firebase-installations`, and their support artifacts. FCM identifies the device with the Firebase installation id, not with an advertising id.
- The device identifiers the app does hold are the FCM token and the pairing material described in **Push notification pairing**. Both go only to the paired KyPost relay.

## Build and test

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

### Release builds

`:app:assembleRelease` **fails without signing material**, and that is deliberate: AGP does not fall back to the debug keystore, so without the guard the build emits an unsigned `app-release-unsigned.apk` on a green run. Add a `keystore.properties` at the repository root (it is gitignored):

```properties
storeFile=/absolute/path/to/your.jks
storePassword=…
keyAlias=…
keyPassword=…
```

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
