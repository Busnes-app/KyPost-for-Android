# Assurance case

[Product overview](../README.md) · [Security](../SECURITY.md) · [Contributing](../CONTRIBUTING.md)

This is the argument that KyPost for Android meets its security requirements: what it protects,
from whom, where the trust boundaries are, and why the design and the code hold at each one. The
detailed behaviour, with every known limitation, is in [SECURITY.md](../SECURITY.md); this page ties
it together and points at the evidence. Paths are relative to
`app/src/main/java/org/kysecurity/mail/` unless they start with `app/` or `.github/`.

## What the app must protect

KyPost holds a pairing credential for someone's mail account and caches their mail, contacts and,
after deliberate enrollment, their PGP key. Its security requirements, from the
[user contract](../CONTRIBUTING.md#the-user-contract) and [SECURITY.md](../SECURITY.md):

1. **The pairing credential reaches only the paired relay,** over TLS pinned at pairing, and never
   over a downgraded connection.
2. **Cached mail at rest is unreadable offline,** and with Hostile Location Protection on, it is
   never written to disk at all.
3. **The app lock holds.** Guessing is slow and bounded, and the wipe that ends it reports what it
   could not erase rather than claiming success.
4. **Hostile mail cannot act.** A message cannot run script, fetch remote content without the
   user's say-so, reach the app's files, or open links by itself.
5. **PGP trust comes from this device,** not from the relay.
6. **No silent fallbacks.** A missing pin, key or setting fails closed. KyPost never archives,
   deletes or moves mail on its own.
7. **New OpenPGP operations meet the local strength policy.** A short key, disabled algorithm
   or weak subkey binding cannot authorize encryption, signing or a positive signature badge.
   Archive decryption and exact historical key retention remain available.
8. **Every connection meets the TLS floor.** TLS 1.2+ with forward-secret AEAD suites, and RSA
   >= 2048 / EC >= 256 keys with SHA-2 signatures across the validated path. "Refuse legacy
   encryption" closes the remaining archive-read exception
   ([STRONG-CRYPTO.md](STRONG-CRYPTO.md)).

## Threat model

| Attacker | Can | Wants |
|---|---|---|
| Network attacker after pairing | Read and alter traffic | Steal the device secret, read mail |
| Compromised or malicious relay | Send any response, push or key | Forge a "signature confirmed" badge, exhaust memory, get plaintext of encrypted mail |
| Sender of a hostile email | Control HTML, links, attachments and headers | Run script, track opens, phish through in-app navigation, read app files |
| Another app on the phone | Call exported components, send intents and pairing links | Re-pair the app to its server, read mail or attachments |
| Someone holding the phone | Guess the PIN, take backups or screenshots, read Recents | Open the app, read cached mail |
| Someone with a forensic image or backup | Read the app's files | Recover mail, contacts or credentials |

Out of scope ([SECURITY.md](../SECURITY.md#what-is-out-of-scope)): a rooted or compromised phone,
screen capture or accessibility abuse by other apps, the mail server itself, and attachments after
they leave the app.

## Trust boundaries

1. **App → relay.** Every request to the relay uses the `pairingHttpClient` built in `PairingAuthHeaders.kt`. It
   follows no redirects, because OkHttp does not strip custom credential headers on a cross-host
   redirect, and it caps response bodies (8 MiB for JSON by default). After pairing, the client
   pins the server's leaf SPKI (`push/PinnedCallFactory.kt`). A request to any other host is
   refused, and a pin that existed and is gone fails closed (`TlsPinState.Lost`). Cleartext is
   off app-wide (`app/src/main/res/xml/network_security_config.xml`). The same client offers only
   TLS 1.2+ ECDHE AEAD suites, and `security/StrongTls.kt` refuses a platform-validated path with a
   key below RSA-2048/EC-256 (anchor included) or a non-SHA-2 signature. `SourceRulesTest` keeps
   every other client and raw socket out of the code.
2. **Pairing link → app.** Pairing is trust-on-first-use. A pin carried in the pairing link
   narrows the TOFU window to one key; a pin that does not parse fails the pairing
   (`normalizeSpkiPin`). The registration URL must be same-origin with the server
   (`push/NativeRegistration.kt`).
3. **Mail content → renderer.** HTML is cleaned with jsoup's `Safelist.relaxed()`
   (`mail/QuotedHtmlSanitizer.kt`). The WebView has JavaScript, file access, content access and
   DOM storage off and network loads blocked. Navigation needs a real tap on an `http`, `https`,
   `mailto` or `tel` link, and web links are confirmed first (`EmailDetailActivity.kt`).
4. **Other apps → KyPost.** A build task, `checkExportedComponents*`, fails if the merged
   manifest exports any activity, service, receiver or provider outside an allowlist. CI runs it
   for all three flavors. Lint's checks for exported services, receivers and providers without a
   permission are fatal too (`app/build.gradle.kts`).
5. **App → its own storage.** The mail database is SQLCipher-encrypted with a random 32-byte key
   held in Keystore-backed preferences (`security/DatabaseKey.kt`, `data/DataRuntime.kt`). The
   device secret is wrapped under a PIN-derived, Keystore-peppered key
   (`security/CredentialCipher.kt`).

## Secure design principles applied

- **Least privilege.** The device secret authorises push, pull, contact sync and MFA response,
  never webmail sign-in. Contacts from other accounts upload only from accounts the user picks.
  Only the fdroid build asks for CAMERA, and CI checks that.
- **Fail-safe defaults.** HLP tampering fails towards **enabled** (`security/HostileLocationSettings.kt`).
  A lost pin refuses to connect rather than falling back to system trust. The wipe's deregistration
  call is refused when no pin was captured.
- **Complete mediation.** Each request is checked against the current pin's host. The pinned
  client and its pin are published as one reference, so a re-pair cannot leave a stale client.
- **Economy of mechanism.** Standard platform pieces where they exist: OkHttp, SQLCipher, the
  Android Keystore. jsoup and Bouncy Castle are the only third-party parsers of hostile HTML and
  OpenPGP input. CONTRIBUTING gives those the highest scrutiny.
- **Separation of privilege.** On-device decryption needs both a deliberate enrollment and HLP
  off, and the envelope's key needs the device's secure lock screen.
- **Open design.** Only published algorithms: TLS, AES-256-GCM, RSA-OAEP, HMAC-SHA-256,
  PBKDF2-HMAC-SHA-256, SQLCipher and OpenPGP. Device enrollment opens RFC 9180 HPKE (v4/v5); the
  older v2/v3 ECDH+HKDF+AES-GCM composition is still opened until the server stops sealing it.
- **Psychological acceptability.** Every trade-off is written where the user reads it: TOFU
  pinning, Play Services in the QR path, FCM payload visibility, RSVPs sent unencrypted
  ([SECURITY.md](../SECURITY.md), [CONTRIBUTING.md](../CONTRIBUTING.md#security-trade-offs-and-when-a-feature-gets-rejected)).

## Common weaknesses and how they are countered

| Weakness | Counter | Where |
|---|---|---|
| Cleartext or downgraded transport | `cleartextTrafficPermitted="false"`; SPKI pin enforced after pairing; a lost pin fails closed | `app/src/main/res/xml/network_security_config.xml`, `push/PinnedCallFactory.kt` |
| Credential leak by redirect or wrong host | `followRedirects(false)` and `followSslRedirects(false)`; a request to a host other than the pinned one is refused | `PairingAuthHeaders.kt`, `push/PinnedCallFactory.kt` |
| Memory exhaustion from a hostile relay | Response bodies capped by Content-Length and while streaming; 8 MiB default for JSON | `PairingAuthHeaders.kt` (`BodySizeLimitInterceptor`), `MemoryBudget.kt` |
| Script in hostile mail (XSS) | jsoup `Safelist.relaxed()`; `javaScriptEnabled = false`; `SetJavaScriptEnabled` is a fatal lint error | `mail/QuotedHtmlSanitizer.kt`, `EmailDetailActivity.kt`, `app/build.gradle.kts` |
| Tracking and remote content | `blockNetworkLoads = true`; "show images" lifts only image loads, on a stripped body | `EmailDetailActivity.kt` |
| Local file access from mail | `allowFileAccess = false`, `allowContentAccess = false` | `EmailDetailActivity.kt` |
| Navigation and scheme abuse | Navigation needs a tap; only `http`, `https`, `mailto` and `tel`; web links confirmed | `EmailDetailActivity.kt` (`SAFE_LINK_SCHEMES`) |
| Forged PGP signature badge | Signer keys resolved from the local contact store; fingerprints computed on the device; the relay's `verified` flag is parsed but nothing that decides a verdict reads it | `pgp/SignerBinding.kt`, `pgp/PgpFingerprint.kt` |
| Weak TLS keys, signatures or suites | `RESTRICTED_TLS` only; chain-wide RSA >= 2048 / EC >= 256 and SHA-2 signatures on the validated path, checked after platform trust | `PairingAuthHeaders.kt`, `security/StrongTls.kt` |
| Broken ciphers in received OpenPGP mail | Plaintext, single DES, SAFER and unknown session ciphers refused before decryption; integrity mandatory; "Refuse legacy encryption" also refuses short keys and 64-bit-block ciphers | `pgp/PgpDecryptor.kt`, `pgp/PgpStrengthPolicy.kt`, `security/CryptoPolicySettings.kt` |
| Obsolete OpenPGP keys or digests used for new trust | RSA >=2048 bits; supported elliptic keys >=224 bits; strong primary/subkey and binding required; only SHA-256/384/512 and SHA3-256/512 signatures can earn a badge | `pgp/PgpStrengthPolicy.kt`, `pgp/PgpEncryptor.kt`, `pgp/PgpDecryptor.kt`, `pgp/SignerBinding.kt` |
| PGP key delivered to the wrong device, or the device's enrollment key exposed | Envelope opened only against the server's delivery record; device ID, fingerprint and version bound as HPKE `info` (v4/v5) or GCM AAD (v2/v3), built from local values; the P-256 agreement key is non-exportable in the Keystore and HPKE runs over its ECDH output (CFRG vector, browser-sealed and Keystore tests) | `pgp/EnrollmentCeremony.kt`, `pgp/HpkeRecipient.kt`, `pgp/DeviceEnvelope.kt`, `pgp/EnrollmentKeyStore.kt` |
| Exported component abuse | Every exported component checked against an allowlist by `checkExportedComponents*`; lint's `ExportedService`, `ExportedReceiver` and `ExportedContentProvider` fatal | `app/build.gradle.kts` |
| Secrets at rest | SQLCipher database with a random 32-byte key; device secret AES-256-GCM wrapped under a PIN-derived, Keystore-peppered key | `security/DatabaseKey.kt`, `security/CredentialCipher.kt` |
| PIN guessing | PBKDF2-HMAC-SHA-256 with 150,000 iterations and a Keystore HMAC pepper (StrongBox first), so guessing stays on the device wherever the Keystore is hardware-backed; a software-only pepper is logged as an error; attempts 1–2 free, then 30 s rising to an hour; wipe after 30 failures by default (10, 20 or 30, or off) | `security/PinHasher.kt`, `security/CredentialCipher.kt`, `security/LockoutPolicy.kt` |
| Incomplete wipe presented as clean | The wipe reports failed steps, resumes up to 3 times, then blocks the app instead of showing first-run | `security/SecurityWipe.kt` (`MAX_WIPE_RESUMES`) |
| Tampering with a security setting | The HLP flag carries an HMAC under a Keystore key; written with `commit()` | `security/HostileLocationSettings.kt` |
| Secrets on screen or in backups | `FLAG_SECURE` windows; `allowBackup="false"` | `security/SecureWindow.kt`, `app/src/main/AndroidManifest.xml` |
| Weak randomness | Keys, salts, IVs and tokens from `SecureRandom` | `security/CredentialCipher.kt`, `security/DatabaseKey.kt`, `push/NotificationIntentToken.kt` |
| Vulnerable or tampered dependencies | `gradle/verification-metadata.xml` pins 577 components, and CI fails if a build changes it; Dependabot with a 7-day cooldown | `.github/workflows/ci.yml`, `.github/dependabot.yml` |
| Signing key exposure | Release secrets only in the protected `release` environment, never on a `pull_request` trigger; `checkSigningSecretsAreNotInTheTree`; signer checked against `RELEASE_KEY_SHA256` before publishing | `.github/workflows/release.yml`, [VERIFYING-RELEASES.md](VERIFYING-RELEASES.md) |

## Residual risk

The full list, with costs, is in [SECURITY.md](../SECURITY.md). The largest:

- TOFU pinning cannot detect an attacker who is present at pairing.
- Historical OpenPGP keys and weak bindings remain parseable for archive decryption and identity
  lookup, never new use or positive trust; valid old revocations still remove trust. Existing v3
  keyring replacement limits remain; [migration guidance](../SECURITY.md#openpgp-strength-and-existing-keys)
  explains how to retain archives. By default old mail still decrypts with short keys and
  64-bit-block ciphers; [STRONG-CRYPTO.md](STRONG-CRYPTO.md) states the risk, and "Refuse legacy
  encryption" closes it. New messages use SEIPD v1 (SHA-1 MDC, CFB) because recipients do not yet
  read SEIPD v2. TLS 1.2 handshake signature algorithms are Conscrypt's, not the app's.
- FCM payloads are readable by the push relay and Google; with Content Preview on, they include
  the sender and subject.
- The QR scanner on Play and GitHub builds is Google Play Services code.
- Attachments saved while HLP is off and then moved or shared are beyond the wipe.
- jsoup is held at 1.23.1 (`gradle/libs.versions.toml`). Advisory GHSA-65r4-943x-97jj, fixed in
  1.23.2, affects only `XmlTreeBuilder`, and no source file uses jsoup's XML parser. 1.23.2 is held
  back because it breaks an mXSS sanitizer test.
- No test or tool enforces "no secrets in logs". A review of the 48 log calls that interpolate a
  value found names, counts, step names and URIs, not credentials or mail content. Exceptions are
  logged with their messages.
- Releases carry no build-provenance attestation, and the release APK cannot be rebuilt to the
  same bytes ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

## Evidence

- **Tests:** JVM unit tests and instrumented device suites. CI runs the unit tests and
  lint for all three flavors, a release build with R8 and manifest checks, emulator suites per
  flavor, and release smoke tests of the minified Play and F-Droid builds on every pull request
  (`.github/workflows/ci.yml`, `release-smoke.yml`).
- **Static analysis:** CodeQL on every push and pull request to `main`, weekly and on demand
  (`.github/workflows/codeql.yml`). Android Lint with a security-focused fatal list. OpenSSF
  Scorecard.
- **Dynamic analysis:** the instrumented and release-smoke suites on emulators. There is no fuzzing.
- **OpenPGP policy:** `PgpStrengthPolicyTest` independently generates RSA-1024/2047/2048,
  short and supported EC keys, DSA and digest/binding fixtures. It covers both signature formats,
  complete-send refusal, positive controls, retained archive bytes, old-mail decryption and
  key-change/revocation precedence, plus session-cipher refusal and the strict setting.
- **TLS and cipher floor:** `StrongTlsTest` (real fixture paths), `StrongTlsDeviceTest` (real
  Android handshakes on loopback, each weak case first shown to pass the platform alone) and
  `scripts/strong-crypto-negative-controls.sh`, which removes each guard and requires a failure.
- **Review:** every pull request needs green CI and an adversarial review pass
  ([CONTRIBUTING.md](../CONTRIBUTING.md#every-pr-must-pass-hostile-ai-code-review)).
- **Releases:** signed APK, signer checked before publishing ([VERIFYING-RELEASES.md](VERIFYING-RELEASES.md)).

This case is updated when a trust boundary or a security requirement changes. A pull request that
moves one must update this page in the same change.
