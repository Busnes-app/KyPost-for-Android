# Store screenshot harness

Throwaway relay + demo IMAP stack and an emulator recipe for the Play listing shots.
Secrets, TLS keys and raw shots go to `$SHOTS_WORK` (default `$XDG_RUNTIME_DIR/$SHOTS_PROJECT`; refused if it is a symlink or not yours), never here.
Run every script with `bash` explicitly. `bash test-env.sh` checks the work-dir guard.

## Settings (env, see `env.sh`)

| Var | Default | |
|---|---|---|
| `ANDROID_SERIAL` | required | the screenshot emulator; other emulators stay untouched |
| `SHOTS_PROJECT` | `kypost-tabletshots` | compose project + volume prefix |
| `SHOTS_PORT` | `15867` | relay on host loopback; emulator uses `https://10.0.2.2:$SHOTS_PORT` |
| `SHOTS_NET` | `172.31.78` | compose /24 |

## Prerequisites

- Images `kypost-demo-mail:local` and `ghcr.io/busnes-app/kypost-server:main`.
- A rooted (`google_apis`, not `playstore`) AVD, booted. `-writable-system` is not needed.
- APK: `assemblePlayDebug -PallowScreenshots=true -PenableReviewPairing=true`, built with the
  real `app/google-services.json`. The CI placeholder builds, but pairing then fails with
  "Unable to obtain a push registration token".

## Run order

1. `bash stack-up.sh`: TLS CA, compose up, waits for a healthy relay.
2. `bash unlock-account.sh`: rotates the bootstrap password and sets IMAP and the label allowlist.
   The relay locks the account after failed logins (429), so don't loop it.
3. `bash seed-mail.sh`, `bash seed-contacts.sh`, `bash seed-contact-keys.sh` (all idempotent).
4. `bash inject-ca.sh`: trusts the CA until the emulator reboots.
5. `bash device-prep.sh <apk> portrait|landscape`: install, rotation lock, demo status bar (9:41).
6. Pair. On the "Push Notifications" screen, tap `btnPasswordPairing`, then fill
   `fastPairServer` / `fastPairUsername` (`sam`) / `fastPairPassword` (`$WORK/admin.pass.new`).
   Press ENTER to hide the IME, tap `btnPasswordPair`, then `button1` (PAIR), then "NOT NOW".
7. Shots, navigating with `bash tap-id.sh <id|text|content-desc>`; capture each with
   `bash shot.sh <name>` (it refuses while the IME is up):
   1. Inbox, All tab. 2. Tap `Primary · 2`. 3. Tap `Re: Q4 roadmap draft` (split on tablets).
   5. BACK, `nav_contacts`, `More options` > `Sync now`, then open a contact.
   4. `nav_compose`. Tap `recipientInputField`, type `Maya`, then tap the suggestion (the popup
      isn't in the uiautomator dump, so read its position off a screenshot). Tap
      `composeSubjectField` with the IME hidden (otherwise the text lands in To), then tap
      `composeBodyPlaceholder` (WebView) and type the body. Hide the IME, then swipe the body
      down to scroll it to the top.
   6. `adb shell am start -n org.kysecurity.mail/.security.SecuritySettingsActivity`, toggle
      `Require Unlock to Open`, and set an 8-12 digit PIN (`PIN`, `Confirm PIN`, `CONFIRM`).
8. `bash finalize.sh <WxH> <fastlane images dir> <raw1> ... <raw6>`: PNG24, no alpha, size check.

## Teardown

`docker compose -f "$SHOTS_WORK/compose.yml" down -v`, then `rm -rf "$SHOTS_WORK"`.
