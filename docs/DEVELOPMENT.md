# Development

[Product overview](../README.md)

Commands and unlinked file paths below are relative to the repository root.

## Firebase setup

Firebase is required for the `play` and `github` build variants only:

1. Register `org.kysecurity.mail` and/or `org.kysecurity.mail.github` in your Firebase project for the variants you intend to build.
2. Download `google-services.json` with the matching client entries and place it at `app/google-services.json` (gitignored).
3. Enable FCM and configure the paired backend’s native push delivery.

The `fdroid` variant contains no Google/Firebase code and disables its Google Services
processing tasks. It needs neither a Firebase app entry nor `google-services.json`; its
pull-based operation does not qualify FCM delivery. On Play/GitHub, a missing matching
client fails `process<Variant>GoogleServices` rather than silently disabling push.

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
[keystore.properties.example](../keystore.properties.example). Preserve the release signer
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
