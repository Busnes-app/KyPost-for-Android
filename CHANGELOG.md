# Changelog

## Unreleased

### Changed

- Remove Pairing keeps the contacts on this phone unless you tick "Also remove this device's
  contacts". It warns when contact changes have not synced yet and offers Sync now. Pairing a
  different account, or pairing after adding contacts while unpaired, asks "Bring your N contacts
  into <server>?" before anything is uploaded; Remove them deletes them from the phone.
- Push keeps working after Firebase rotates its token or you switch between Firebase and
  UnifiedPush: the app refreshes its registration with its own device key instead of the
  one-time pairing code (needs a KyPost server with `native/refresh`; older servers behave as
  before).
- A pairing link that would trust a new certificate for the same server now says "This server's
  certificate changed since you paired" before you continue.
- Encrypted or signed replies stay in their conversation, like plain replies.
- Leaving a message you are writing offers Save draft where this device can save drafts.
- Accounts whose encryption key is held by the server can save drafts too (menu and when leaving
  a message), as on the web. A message marked Sign or Encrypt is not saved this way.

### Fixed

- Sharing a file into KyPost while another message was open no longer blanks that message's
  attachments.
- A contact with a job title but no company keeps its title when edited in the phone's Contacts
  app, and moving a contact between groups on the web now updates the phone.
- After unpairing or switching accounts, mail, notifications and encryption settings still loading
  for the old account no longer appear under the new one, and an old compose screen closes.
- A device approved on the web while KyPost was locked finishes pairing after unlock, and the
  result shows even if the pairing screen was reopened.
- Switching this phone to another account stops the previous account's notifications: its
  device is removed from its server first.
- Restarting the phone during a PIN lockout no longer extends it for days.
- Two attachments saved to Downloads at the same moment are both removed by a later wipe.
- A snoozed message that wakes, or a message moved out and back, shows again in the folder.
- Rotating the phone no longer loses a message you are writing after another reply was sent or
  discarded in the meantime, and Reconnect no longer closes it.
- Forward waits until a message's attachments have loaded instead of leaving them out.
- Scanning a PGP code from someone on another KyPost server works.
- Bringing contacts into a new account leaves out PGP keys that server would refuse, so those
  contacts sync.
- An approved switch to another account now says it is paired and asks about contacts.
- A link for a different server than the one this phone is paired with says to unpair first,
  instead of failing after you confirm.
- The Unpair dialog opens even when the local database cannot, and says that contacts' copies in
  the phone's Contacts app are removed.
- A contact form left open across an account switch closes instead of saving into the new
  account.

## 0.6.0 — 2026-11-02

### Added

- New-device approval (KyPost-Server #516). After a pairing QR code or link, the server holds the
  device until you approve it on the web page that showed the code. Pairing shows a "Waiting for
  approval" card with the same 6-digit code and the server's name, so you can check they match,
  and a Cancel button. Approved, it finishes pairing as before. Denied or timed out, it says "Not
  approved: denied or timed out. Scan a new code." KyIdentity sign-on and review pairing still
  pair at once. A code someone else already used is now named as such.
- Before contact sync reads or sends any contacts, KyPost shows Google Play's prominent
  disclosure: what is sent, the address of the KyPost server it goes to, and why, with Agree and
  Not now. Not now leaves sync off and the app working. The choice is stored for that server, and
  Settings has a Contact sync row that shows it and turns it off (#282).

### Changed

- The contact sync disclosure now also says how your KyPost server uses uploaded contacts
  (address book sync, recipient suggestions, signature checks, Primary sorting and encryption-key
  lookups, which send the address to the recipient's mail domain and keys.openpgp.org), that it
  stores them unencrypted, and how long they are kept. It matches KyPost for iPhone, iPad and Mac.

- Contact sync turned on in an earlier version stays off until you agree to the new disclosure.
  Pairing no longer offers contact sync before the server is known; turn it on in Settings or
  Contacts after pairing. Turning sync off also clears the accounts picked under Import from
  other accounts.

- The top bar shows the logo and an ink "KyPost", then the page name as its own title. The
  ALL-CAPS label under the brand is gone, and button labels are sentence case.
- The bottom bar and the rail use outline icons and mark the open screen with a soft accent pill.
  They sit flat with a hairline edge. On wide screens the rail's items start at the top.
- Settings is a list: an icon, the title over its description, and a chevron per row, with
  hairlines between rows, up to 720dp wide.
- One filled button per group. Pairing keeps Scan QR code filled; the other actions are outlined,
  and Unpair stays red. Contact edit's "Add" actions are text buttons.
- Cards are flat with a thin line, and selected chips and rows use a soft accent tint instead of
  a solid accent fill.
- Pairing uses the "KyPost | Pairing" top bar. "Scan QR code" is a flat filled button in the
  pairing card instead of a bar pinned to the bottom, and the other ways to pair sit under it.
- The inbox's keyword chips sit on the page, without a card behind them.
- Pairing's empty notification history is a flat card with a thin line, directly under its
  label and inset like the cards above it, instead of a dashed box across the full width.

## 0.5.1.4 — 2026-10-31

### Added

- Each release also carries `kypost-fdroid-vX.Y.Z.apk`, the `fdroid` build signed with the
  KyPost release key. F-Droid rebuilds it from source and publishes ours only if the rebuild
  matches (#287). APKs no longer include Google's encrypted dependency-info block.
- On Play, tapping "Use Firebase" 10 times on a device that has never paired opens the review
  login, for Play's reviewers (#285).

### Changed

- Themes are now the six Ky suite light/dark pairs: Busnes (default), Matter, Ocean, Forest, Ky
  and Nord. Pick a pair plus System default, Light or Dark. A saved surviving half keeps that half;
  a removed palette resets to Busnes following the system.
- Danger, warning and success use each half's own status colours instead of fixed ones, with a
  dot beside the word. This covers delete buttons, warning callouts, status badges, swipe
  reveals, the unlock error, pairing status and the contact sync banner.
- Foldables: the navigation rail on wide windows (an unfolded book-style foldable, anything at
  least 600dp wide) sits on the right by default, and Themes has a new Rail position setting,
  Right or Left. A half-open book-style foldable splits the inbox and message at the hinge.
  Squarish flip cover screens narrower than 440dp now keep the phone's bottom bar.

### Fixed

- In landscape, a display cutout or a side navigation bar no longer covers the edge of a screen.
- `assembleFdroidRelease` builds an unsigned APK when no signing material is set, as F-Droid
  needs, instead of refusing. Play and GitHub release packaging still refuses without it (#286).
- Store listing title, summary and description in `fastlane/metadata/android/en-US`, which
  F-Droid reads for its listing (#286).

## 0.5.1.3 — 2026-10-30

### Fixed

- With the keyboard up, the bottom bar sits on top of the keyboard instead of leaving a
  keyboard-sized gap above it that squeezed the compose fields (#283). The side rail on wide
  screens and foldables gets the same fix.

## 0.5.1.2 — 2026-10-29

### Dependencies

- Firebase BoM 34.2.0 → 35.1.0, DataStore Preferences 1.1.7 → 1.3.0, kotlinx.serialization
  1.11.0 → 1.12.0, Android Gradle Plugin 9.4.1 → 9.5.0, with their verified checksums.

## 0.5.1.1 — 2026-10-28

### Security

- Device enrollment accepts only RFC 9180 HPKE envelopes (v4/v5). The app advertises
  `envelopeVersions: [4, 5]` and the custom v2/v3 opener is removed. A server that delivers v2/v3
  gets "update your KyPost server" and nothing is saved or acknowledged. KyPost-Server #492 and
  later deliver v4/v5. Devices already enrolled are unaffected: the vault stores the opened key,
  never an envelope.
- Every connection now requires TLS 1.2 or 1.3 with an ECDHE AEAD cipher suite, RSA >= 2048
  or EC >= 256 keys on every certificate of the validated chain (trust anchor included) and
  SHA-2 certificate signatures. A server below that fails to connect.
- Received OpenPGP mail that uses plaintext, single DES, SAFER or an unknown session cipher is
  refused.
- New setting: Security → Encryption strength → **Refuse legacy encryption**. Off by default;
  when on, old mail that needs a key below RSA-2048 / 224-bit EC or a 64-bit cipher (IDEA,
  3DES, CAST5, Blowfish) is not opened. Nothing is deleted. Turning it off asks for the PIN.
- [docs/STRONG-CRYPTO.md](docs/STRONG-CRYPTO.md) lists every algorithm and key size the app
  uses and documents the old-mail exception.
