# Changelog

## Unreleased

### Changed

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
