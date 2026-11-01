# Connections

[Product overview](../README.md)

Commands and unlinked file paths below are relative to the repository root.

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

## Notification permission behavior (Android 13 and later)

- The app requests `POST_NOTIFICATIONS` at launch.
- If the user denies the permission, the app still parses each delivered push payload and saves it to the in-app history. The app does not show system notifications.

## Pairing from a desktop QR code

1. The desktop web app shows a QR code with the deep link. The link contains `sub`, `srv`, `pt`, and optionally `reg`.
2. On the Pairing screen, tap **Scan QR code**. You can also open the deep link directly, because the app is a handler for `kypost://native-pair`.
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
