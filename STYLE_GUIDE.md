# Visual Style Guide — aligning with the KyPost family

This app is a sibling to three other clients for the same product/account/brand:
the web app (`../llama labels/frontend`), the iOS/macOS app (`../llama-Mail-for-Mac`,
shared SwiftUI codebase), and the Linux Mobile app (`../llama-Linux`, Qt/QML,
convergent desktop+mobile). All four should read as clearly the same product — same
colors, same shape language, same component vocabulary, same motion feel — while each
still feels native to its platform, not a skin of another platform's UI. When a rule
below would force a non-native pattern (e.g. a custom modal instead of `AlertDialog`),
the "stay native" column wins; see [Section 6](#6-what-to-keep-native--do-not-copy-literally).

iOS and Linux Mobile are the more useful reference points day to day: they're native,
touch-first (or convergent) apps like this one, so "does it look like them" is a better
question than "does it look like the web app." Colors, radii, and font choices still
trace back to the same source values as web, though — nothing below is iOS/Linux
inventing new design decisions independent of web.

Source of truth for colors: ky-ui (`src/themes.js` `THEME_PAIRS`, `src/tokens.css`), which the web
apps consume directly. Android mirrors it in `AppTheme.kt` `THEME_PAIRS`. The October 2026 pairs
pass reached web and this app first; iOS/macOS and Linux Mobile follow in their own passes. (Swift
and QML source code already carry `STYLE_GUIDE.md §N` comments pointing back at this file, so keep
section numbers stable when editing.)

## 1. Color system (already shared — keep it that way)

Six light/dark **pairs** replace the old 15 palettes: `Busnes` (default), `Matter`, `Ocean`,
`Forest`, `Ky` and `Nord`. Each has a light half and a dark half. The user picks a pair plus a mode:
System default (follow the OS), Light or Dark. Don't fork this list per platform. A saved choice of
a surviving half keeps that half forced. Every removed palette resets to Busnes following the
system (`ThemeMigrationTest`).

Android's `line` holds the control border **composited onto `panel`**, not its `rgba()` form:
`blend()` in `AppTheme.kt` drops alpha, so a translucent `line` would paint the empty-state dashed
border near-black on cream. ky-ui's `buttonText` needs no palette field. It is what
`readableOn(accent)` already returns on every half.

Web's `ThemeVars` has more fields than mobile's `ThemePalette`. Android derives everything from
`bg/panel/ink/inkStrong/accent/line` plus the status colours, and fakes the avatar gradient with
two derived stops (`avatarGradientStart/End`). Don't add `accentSoft` unless a second component
needs a true theme-driven gradient stop it can't otherwise produce.

**Status colours are per half** (ky-ui 0.8.0), separate from the accent:

| Role | Light halves | Dark halves | Exceptions |
|---|---|---|---|
| Danger / delete / error | `#a8174e` (cool crimson, never the rust accent) | `#ff8fb1` | Nord Dark `#ecc4c8` |
| Warning / archive | `#7a5f00` | `#ffd25e` | |
| Success / active status | `#267442` | `#86efac` | Forest teal `#00737a` / `#6ee0d0`; Nord Dark `#bcd4aa` |
| Soft fill | the status mixed 12% into `panel` (`statusSoft`) | same | |
| Inactive / neutral status | `line`/`panel`/`ink` from the active half | same | |

A status always shows a word plus a dot or icon, never colour alone. The gate is ky-ui's
`scripts/check-status-colours.mjs`, ported as `StatusColourGateTest`: text at 4.5:1 or better on
bg, on panel and on its soft fill; ΔE00 ≥ 20 between accent and danger; and ΔE00 ≥ 10 between any
two of accent, danger, warning and success.

## 2. Typography

Every platform uses **Space Grotesk** (UI text) and **IBM Plex Mono** (code/log/email-body
text). This is already wired up on Android — `themes.xml` sets
`@font/space_grotesk` as the app-wide default `fontFamily` (downloadable font, Google
Fonts provider, zero APK weight), and `@font/ibm_plex_mono` is applied per-view where a
monospace field is called for (`activity_push_pairing.xml`,
`activity_pgp_key.xml`). Linux Mobile bundles both as `.ttf` assets directly
(`fonts/Space_Grotesk`, `fonts/IBM_Plex_Mono`) since Qt has no Google-Fonts-provider
equivalent. iOS references both by name too, but falls back to the system font today
because the `.ttf`s aren't in the Xcode bundle yet (`AppFont.isFontAvailable` — see
`Style/ThemeManager.swift`); that's an iOS-side gap, not something this app needs to
work around.

Remaining Android-specific gap: the email body renderer (`EmailDetailActivity`'s
`WebView`) injects `font-family: monospace` as generic CSS rather than the actual IBM
Plex Mono family — see [§7](#7-android-gaps).

- Space Grotesk → default `TextAppearance` for all UI chrome (toolbar, buttons, labels,
  list rows). Already the global default via `themes.xml`.
- IBM Plex Mono → email body text, log viewers, code/monospace fields, DAV/URL/secret
  display (mirrors `.email-reader-body-block`, `.log-line`, `.contacts-dav-url` on web).
- Respect system font-scale (`sp`, never hardcode `px`-equivalent fixed text) even where
  matching a fixed web `rem` scale — accessibility wins over pixel-parity. iOS/Linux make
  the same trade (Dynamic Type / Qt's own scale-respecting font sizing, respectively).

Reference sizes actually used by iOS/Linux components today (not hard requirements,
but worth matching when adding new Android views so text density feels consistent):
button label 15, pill/badge label 12–13, section eyebrow label 11–12 with letter-spacing.

## 3. Shape language

Already aligned on Android — this table is now a confirmation, not a to-do list.

| Element | Shared value | Android | iOS (`Shape` enum) | Linux (`Theme.shape*`) |
|---|---|---|---|---|
| Text field / input | 14 | `fieldBackground` cornerRadius 14dp ✓ | `Shape.field` 14 ✓ | `shapeField` 14 ✓ |
| Primary/secondary/danger button | 10 | `buttonBackground`/`ghostButtonBackground`/`dangerButtonBackground` cornerRadius 10dp ✓ | `Shape.button` 10 ✓ | `shapeButton` 10 ✓ |
| Card / panel | 14 | `@dimen/card_corner_radius` / `applyPanelBackground` (`AppTheme.kt`) 14dp ✓ | `Shape.panel` 14 ✓ | `shapePanel` 14 ✓ |
| Modal / bottom sheet | 14 | `AlertDialog`/`BottomSheetDialog` default Material shape — close enough, don't hand-tune | `Shape.sheet` 14 | `shapeSheet` 14 |
| Empty state | 10 | `applyEmptyStateBackground` cornerRadius 10dp ✓ | `Shape.emptyState` 10 ✓ | `shapeEmptyState` 10 ✓ |
| Pill badge, filter tab, segmented toggle | full stadium (`radius = height / 2`) | `applyPillChipTheme` via Material `Chip` (stadium by default) ✓ | `Capsule()` ✓ | `radius: height / 2` ✓ |
| Avatar | circle | `bindAvatar` `GradientDrawable.OVAL` ✓ | `Circle()` ✓ | `radius: width / 2` ✓ |

## 4. Component patterns

Each maps to the same named concept across all four apps, so intent stays traceable.
Status column reflects what's actually in the Android codebase today, verified against
the equivalent iOS (`Presentation/Components/`) and Linux (`app/qml/components/`) views.

- **Primary button** — solid `accent` fill, 10dp radius, text color = `readableOn(accent)`.
  **Done** (`applyPrimaryButtonTheme`). Touch feedback is Material ripple, not iOS/Linux's
  opacity dip on press — see §6.
- **Ghost/secondary button** — transparent fill, 1dp `line` stroke, `inkStrong` text.
  **Done** (`applyGhostButtonTheme`).
- **Danger button** — 1dp danger stroke over the half's danger soft fill, danger text (§1),
  never theme-accent. **Done** (`applyDangerButtonTheme`).
- **Floating action button** — `accent` fill, icon tinted `readableOn(accent)`. **Done**,
  for every FAB in a themed view tree (`applyThemeToViewTree`); pinned by
  `ContactsFabThemeTest`.
- **Pill filter tabs / segmented toggle** — stadium chips; inactive = opaque `panel` fill
  (not literal transparent — see the code comment on `applyPillChipTheme` for why) + `line`
  stroke, active = `accent` fill + `readableOn(accent)` text. **Done**, via Material
  `Chip`/`ChipGroup` rather than a hand-rolled view (matches iOS's native
  `Capsule`-backed toggle and Linux's `PillTab.qml` — every platform prefers its native
  chip/pill primitive over reimplementing the shape from scratch).
- **Status badge + dot** — pill outline badge with a small leading circular dot, colored
  by the §1 status colours (`StatusTone`). Used anywhere a contact/user/device shows an
  active-vs-inactive state. iOS has `StatusBadgeView.swift`, Linux has `StatusBadge.qml`.
  **Missing on Android** — see [§7](#7-android-gaps).
- **Circular gradient avatar with initials** — 34dp (list) / 52dp (detail header) circle,
  two-stop accent gradient fill, 1dp border, initials in `readableOn(accent)`. **Done**
  (`bindAvatar`).
- **Empty state** — dashed 1dp border in an accent-tinted line color, centered muted
  text, 10dp radius. **Done** (`applyEmptyStateBackground`).
- **Section eyebrow label** — small uppercase, letter-spaced, ~72%-opacity `inkStrong` —
  group headers only, not body copy. **Done** (`applySectionEyebrowLabel`).
- **Swipe-to-archive/delete on list rows** — doesn't exist yet on *any* platform's inbox
  list. If/when swipe gestures are added, use `ItemTouchHelper` on Android with the same
  red=delete / yellow=archive reveal coloring as the other platforms. Not required now —
  noted so it isn't accidentally built with mismatched colors later.

## 5. Motion

iOS and Linux Mobile both converged on the same figure independently: **120ms**, eased.
iOS uses `.animation(.easeInOut(duration: 0.12), value: ...)` on button press-opacity and
theme-driven color changes; Linux uses `Behavior on color/opacity { ColorAnimation {
duration: 120 } }` for the same two cases (pill/badge active-state color swaps, button
press-opacity). Treat 120ms as the shared timing constant, not a web-only value — match
the duration on Android using standard `ObjectAnimator`/`ViewPropertyAnimator` timing
(`FastOutSlowIn` interpolator) rather than porting either platform's exact easing curve,
which was tuned for its own animation system.

Android currently has no equivalent — see [§7](#7-android-gaps).

## 6. What to keep native — do not copy literally

These are the deliberate exceptions, not oversights. They apply regardless of which
sibling app (web, iOS, Linux) you're comparing against.

- **Navigation shape.** Don't build a literal left sidebar (web) or import Linux's
  desktop-rail layout. Android convention is a toolbar + overflow menu (current
  approach) or bottom navigation; keep whichever the app already uses. Wide windows
  (600dp and up, an unfolded book-style foldable) swap the bottom bar for a Material
  `NavigationRailView`, on the right by default; the user can move it left (Themes →
  Rail position). Tall foldables and cover screens keep the bottom bar.
- **Dialogs/sheets.** Don't hand-roll a backdrop+window to mimic a custom web/QML modal.
  Use `AlertDialog` / `BottomSheetDialog`, themed with the active palette — they already
  get back-button handling, gesture dismiss, and TalkBack support for free.
- **Press feedback.** Keep Material ripple on touch instead of porting iOS/Linux's
  opacity-dip-on-press or web's `translateY(1px)` hover (Android has no hover state to
  begin with, and ripple is already the platform-idiomatic equivalent — this is *not*
  one of the Android gaps in §7).
- **Chrome theming.** The existing edge-to-edge status/nav-bar repaint in
  `applyThemeToActivity` is already a good native-parity win — don't regress it while
  closing the gaps below.
- **Font scale.** Always `sp`, always respects system accessibility text size, even when
  visually targeting a fixed point/pixel value from another platform.

## 7. Android gaps

All three gaps previously tracked here are closed. Kept as a record of what was done and
why, not a to-do list — don't re-verify unless you suspect drift.

1. **Email body monospace font — done.** `EmailDetailActivity` injects a base64-inlined
   `@font-face` rule (`AppTheme.ibmPlexMonoFontFaceCss`, sourced from the bundled
   `assets/fonts/IBMPlexMono-Regular.ttf`, Regular weight only) into the `WebView`'s
   `<style>` block instead of generic `font-family: monospace`. Inlined rather than
   referenced via a `file:///android_asset/` base URL deliberately — that WebView renders
   untrusted email HTML with JS enabled, and switching its base URL from `null` would
   grant that untrusted content `file://` origin access.
2. **Status badge + dot component — done.** `AppTheme.applyStatusBadgeTheme` (a `StatusTone`
   paints the half's status colour from §1, neutral = theme-derived `line`/`panel`/`ink`, dot via
   the existing `unreadDotDrawable`) is wired into `ContactAdapter`/`item_contact.xml`,
   keyed off `ContactEntity.pgpKey` presence ("Secure key" / "No key"). The address-book
   picker (`RecipientRowAdapter`) does not show this badge — its `RecipientCandidate`
   DTO doesn't carry `pgpKey`; extending it there is a separate future change, not a gap
   in this component.
3. **Motion on interactive color changes — done, scoped.** `AppTheme.animateChipColorTransition`
   (120ms, `FastOutSlowIn`, per §5) animates `applySuccessChipTheme`'s address-book
   "added" chip transition (`animate = true` at the tap site in `RecipientRowAdapter`).
   `applyPillChipTheme`'s checked/unchecked toggle was deliberately left un-animated —
   its colors are stateful `ColorStateList`s that Chip's own state machine already
   transitions, and this section never required a full pass.
