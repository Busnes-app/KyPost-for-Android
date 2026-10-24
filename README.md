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
channel/package is a separate install and requires pairing again. See [Channels](docs/DEVELOPMENT.md#channels).

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

## Privacy and data collection

The Google/Firebase dependency details below apply to Play/GitHub variants. F-Droid omits those libraries; all variants still send pairing credentials to the chosen server.

- The app does not use the Android advertising ID (AAID). No source file calls `AdvertisingIdClient`, and no merged manifest declares `com.google.android.gms.permission.AD_ID`.
- No advertising or attribution library is in the dependency graph. The resolved Google Play services artifacts are `play-services-base`, `-basement`, `-cloud-messaging`, `-code-scanner`, `-stats`, and `-tasks`. Neither `play-services-ads-identifier` nor `play-services-appset` is present.
- Firebase Analytics is not included. The build pulls `firebase-messaging`, `firebase-installations`, and their support artifacts. FCM identifies the device with the Firebase installation id, not with an advertising id.
- The device identifiers the app does hold are the FCM token and the pairing material described in **Push notification pairing**. Both go only to the paired KyPost relay.

## Documentation

- [Connections](docs/CONNECTIONS.md) — Push notification pairing, Pull mode (FCM and relay bypass), Notification permission behavior (Android 13 and later), Pairing from a desktop QR code, and related procedures. <a id="push-notification-pairing"></a><a id="pull-mode-fcm-and-relay-bypass"></a><a id="notification-permission-behavior-android-13-and-later"></a><a id="pairing-from-a-desktop-qr-code"></a><a id="troubleshooting-checklist"></a>
- [Verifying releases](docs/VERIFYING-RELEASES.md) — Check a release APK's signing certificate and the commit it names, and why a rebuild does not match yet.
- [Assurance case](docs/ASSURANCE-CASE.md) — Threat model, trust boundaries, and why the security requirements hold.
- [Development](docs/DEVELOPMENT.md) — Firebase setup, Build and test, Test coverage. <a id="firebase-setup"></a><a id="build-and-test"></a><a id="release-builds"></a><a id="channels"></a><a id="test-coverage"></a>
