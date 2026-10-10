# Security Policy

KyPost for Android is the companion app to a self-hosted KyPost server. It holds a
pairing credential for someone's mail account, caches their mail, and — depending on
settings — their contacts and attachments. This document covers how to report a
vulnerability and what the app does and does not protect.

For **server-side** security (TLS termination, reverse proxies, key custody at rest,
deployment hardening), see [SECURITY.md in the server
repository](https://github.com/Busness-app/KyPost-Server/blob/main/SECURITY.md).
Report server vulnerabilities there, not here.

## Reporting Security Vulnerabilities

Report vulnerabilities in the Android app via GitHub Security Advisories rather than
opening a public issue.

1. Go to the [Security
   Advisories](https://github.com/Busness-app/KyPost-for-Android/security/advisories)
   page
2. Click "Report a vulnerability"
3. Provide a description, affected versions, and reproduction steps if you have them
4. Do not disclose publicly until a patch is available

If you are unsure which repository a finding belongs to, file it here and it will be
moved. A misfiled report is better than an unfiled one.

### Disclosure Timeline

Matching the server repository, so a finding spanning both is not governed by two
different clocks:

- **Critical** (credential disclosure, authentication bypass, remote code execution):
  30 days
- **High** (privilege escalation, cryptographic weakness, local data disclosure past a
  security control): 60 days
- **Moderate** (denial of service, information disclosure): 90 days

You will get an acknowledgement within 2 business days, a severity assessment, and
credit in the release notes unless you prefer anonymity.

## What the app protects, and what it does not

Read this before relying on any single control. The app is deliberately honest about
where each one stops.

### App lock

A PIN or biometric gate on opening the app (`security/AppLockManager.kt`).

- Wrong-PIN attempts follow an escalating-delay curve: the first two are free, because
  typos happen, and attempt three onward adds a growing delay
  (`security/LockoutPolicy.kt`).
- After `WIPE_THRESHOLD` consecutive wrong attempts with no intervening success, local
  data is wiped (`security/SecurityWipe.kt`).
- **The wipe fails closed.** It reports each step it could not complete rather than
  claiming a clean erasure, and resumes at the next launch. If it still cannot finish
  after three resumes it stops retrying — but it does *not* forget: the marker persists,
  and every launch from then on blocks the whole app behind "manual recovery required"
  instead of presenting a first-run screen over data that is still on disk. Reinstalling
  is the recovery. Only *sandbox* destruction is terminal in this sense: a file in shared
  storage that another process refuses to delete is reported, not treated as a failed
  step, because it cannot be made to succeed by retrying and blocking the app does not
  delete it.
- **Keystore aliases are part of the wipe.** Every alias this app mints is destroyed and
  the deletion is verified, including the two credential peppers — an alias surviving a
  wipe is a durable, attributable record that this app was installed, on a device the
  routine has just described as clean.
- Because an attacker gets a bounded number of guesses, common PINs are rejected at
  set time (`security/PinPolicy.kt`). The sequences and repeats that dominate published
  leaked-PIN datasets would otherwise all fit inside the free guesses.
- A PIN that cannot be *checked* — the Keystore pepper backing the verifier is gone or
  unusable — is deliberately distinct from a wrong PIN and **does not** count toward the
  wipe threshold. Folding the two together meant an OS-level Keystore invalidation made
  every correct PIN read as wrong, and destroyed user data in response to an event the
  user neither caused nor could avoid.

**What it does not do:** the app lock gates the app, not the device. It is not a defence
against an attacker with the device unlocked and the app already open.

### Hostile Location Protection

An opt-in mode (off by default) for users who expect their device to be inspected or
seized (`security/HostileLocationSettings.kt`).

When enabled:

- The Room database is constructed in-memory only, never disk-backed.
- Push history is held volatile rather than persisted.
- Device contact sync is blocked.
- Keyword settings are not persisted.
- Attachments are viewed ephemerally, with no disk write at all
  (`security/AttachmentAction.kt`, `security/EphemeralAttachmentProvider.kt`).
- Notifications carry no sender and no subject, whether or not the app is locked
  (`push/PushNotificationDispatcher.contentSuppressed`). Posting a notification hands its
  title and text to `system_server`, which records them in Notification History and
  `dumpsys notification` — an on-disk record in another UID that no wipe step here can
  reach. Withholding the content is the only control this app has over it.
- Adding a calendar invite, or creating an event from an email, asks first: the event is
  handed to the device's calendar app, which stores it where no KyPost wipe reaches.

**Known limitation — notifications posted before protection was enabled.** Turning the
mode on cannot retract what the OS already recorded. Clear Notification History from
Android's own settings if that matters to you.

The flag is written with `commit()` rather than `apply()`, and *after* the on-disk
database has been deleted, so a process death cannot leave protection off while the user
believes it is on.

**The flag is authenticated.** It is a value plus an HMAC under a non-exportable
AndroidKeyStore key (`KeystoreHlpKey`), and the key's presence is the durable half of the
marker — the same construction as the app-lock tripwire. Without it the setting was a bare
boolean in a private preferences file: anything able to write the app sandbox could turn
protection off, and the next launch would begin persisting decrypted mail to a disk the
user believed was empty, silently. Tampering now fails towards **enabled**, and a Keystore
that cannot be consulted blocks the app with a notice rather than guessing.

**Known limitation — attachments saved while HLP is off.** With protection off (the
default), a single tap writes an attachment to the shared Downloads collection, which is
outside the app sandbox. Nothing the wipe deletes reaches shared storage on its own, so
those files previously survived a wipe, an app-lock reset and a re-pair while the app
reported local data as cleared. `security/DownloadedAttachmentLedger.kt` exists to record
those MediaStore rows so the wipe can remove them, and the row is committed synchronously
*before* the file is written — recorded after, a process death in between leaves a copy
nothing will ever find again. **Files a user has since moved, copied, or opened into
another app are beyond the app's reach entirely.** A row the provider refuses to delete
does not fail the wipe: it is counted and reported to the user on the next launch, because
a permanently blocked app is the wrong answer to a file they can delete themselves.

### Cached mail at rest

`kypost_mail.db` holds every cached message body, the whole contact book and contacts' PGP
keys. It is encrypted with SQLCipher (`security/DatabaseKey.kt`, `data/DataRuntime.kt`).

The passphrase is 32 random bytes held in a Keystore-backed `EncryptedSharedPreferences`
file. It is **not** derived from the app-lock PIN: the database has to open in processes
where no PIN has been entered — an FCM delivery, a background sync — so a PIN-derived key
would either break those or force the PIN to be cached somewhere worse.

**What this protects against:** reading the file offline. Root, an unlocked bootloader, a
forensic image, a stolen backup.

**What it does not protect against:** a live, rooted, running device. Code executing as
this app's UID can ask the Keystore to use the key, exactly as the app does. Hostile
Location Protection is the answer to that threat model, and it is stronger — under it
there is no file at all.

Existing installs are converted in place on first launch after upgrading. The conversion
never deletes the original before the replacement is verified and moved into position.

### Certificate pinning

KyPost is self-hosted with a per-user server URL, so there is no certificate to hardcode.
The server's SPKI pin is captured once at pairing time and enforced on every later
connection (`security/SpkiPinner.kt`, `push/PinnedCallFactory.kt`).

**This is trust-on-first-use.** It detects a certificate that changes after pairing. It
cannot detect an attacker who is already in position *at* pairing. Pair over a network
you trust.

### Pairing credentials

The app authenticates to the server with a device id and a per-device secret
(`X-Kypost-Device-Id` / `X-Kypost-Device-Secret`, see `PairingAuthHeaders.kt`). The secret
is minted by the server at registration and returned exactly once.

- It is wrapped locally under a key derived from the app-lock PIN, peppered with a
  Keystore-held value (`security/CredentialCipher.kt`).
- It authorises push delivery, pull, contact sync, MFA response, and — where enabled —
  enrollment. It is **not** the account password and cannot be used to sign in to webmail.
- Revoke a lost device from the server's Security page. Revocation is per-device.
- The wipe's server-side deregistration is sent over the **pinned** connection, using a
  pin captured before the wipe deletes it. If no pin was captured the call is refused
  rather than downgraded, so a wipe never hands this credential to an unpinned
  connection — at the one moment the device is most likely to be on a hostile network.
  The cost is that the relay may keep the device listed until it is revoked manually.

### Mail content and PGP

- **A signature's "confirmed" badge comes from this device, never from the relay.** The
  signer key is resolved out of the local contact store, whose fingerprints are computed
  here from the key's own bytes (`pgp/PgpFingerprint.kt`). A key the relay supplies can
  still support the weaker *continuity* badge for a first-contact message, but it is capped
  there: the relay's own `verified` flag is not read at all, and a signature that does not
  match a key this device already holds for the sender reports **key changed** rather than
  a badge (`pgp/SignerBinding.kt`). Previously the key, the address it was bound to and the
  `verified` flag all arrived in the same response as the ciphertext, so a compromised relay
  could render "signature confirmed" over a message it had signed itself.
- **Encrypted mail is decrypted on the device**, but only once this device holds a sealed
  key envelope (see below). Until it does — and on any device where enrollment is
  unavailable — encrypted mail is not decrypted here at all: the app hands the message off
  to webmail in the user's own browser, or the installed webmail PWA, and never in a
  Custom Tab. A Custom Tab renders inside KyPost's task, where this app's `FLAG_SECURE`
  does not cover the browser's window, so the Recents preview could show plaintext. See
  `pgp/WebmailTab.kt`.
- **Composing to a recipient's PGP key encrypts on the device.** The plaintext body is
  never sent to the relay for that path.
- **Encrypted mail is excluded from push payloads by the server**, regardless of the
  Content Preview setting, because native push travels through a relay and on to FCM/APNs
  in cleartext at every hop.
#### Device enrollment

- The sealed envelope that makes on-device decryption possible is accepted **gated behind
  Hostile Location Protection** — available only when HLP is off, and destroyed when HLP
  is turned on. It is a deliberate, user-chosen posture change, not a default. The trade
  is recorded in full in
  `docs/superpowers/specs/2026-07-29-on-device-pgp-decryption-design.md`.
- The envelope is unwrapped under a Keystore key that requires the device's secure lock
  screen. A device with no lock screen cannot enrol at all.
- A security wipe destroys the envelope. If it cannot, the wipe reports itself incomplete
  and the app fails closed — see **App lock** above.

### Third-party components in security-relevant paths

Stated rather than left to be discovered:

- **Pairing QR scanning uses Google Play Services** (`play-services-code-scanner`). The
  scanner UI and the module that backs it are Google's, downloaded on demand, and the
  pairing QR passes through them. This is inconsistent with the rest of the app's posture
  — the manifest carries no `<queries>` block specifically so the app cannot see what else
  is installed, and the client refuses to trust the relay with its own public key. If you
  do not want Play Services in that path, pair by entering the URL rather than scanning.
- **Push delivery** is either FCM (Google) or UnifiedPush (a distributor you choose), or
  App Pull, which polls your own server and involves neither. Notification content is
  end-to-end opaque to the push transport; what the transport learns is timing.

### What is out of scope

- **A rooted or compromised device.** Keystore-backed material resists extraction, but an
  attacker with root and the app unlocked is inside every boundary here.
- **Screen capture and accessibility-service abuse** by other installed apps.
- **The mail server itself**, and anything reachable with the account password. Those are
  server-repository concerns.
- **Attachments after they leave the app**, as described above.

## Supported versions

`minSdk` is 31. Security fixes target the current release. There is no long-term support
branch for older versions.

## Security Contacts

- **Vulnerability reports:** [GitHub Security
  Advisories](https://github.com/Busness-app/KyPost-for-Android/security/advisories)
- **Maintainer:** [Yoshiofthewire](https://github.com/Yoshiofthewire)
- **Code of Conduct concerns** are handled separately — see
  [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md). Security vulnerabilities are not a Code of
  Conduct matter.
