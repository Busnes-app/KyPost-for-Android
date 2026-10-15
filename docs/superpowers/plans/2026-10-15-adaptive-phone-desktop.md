# Adaptive Phone, Foldable, Tablet and Desktop — Roadmap Plan

> **For agentic workers:** this is a phase roadmap. Before starting a phase, write a task-level plan
> for it (format: `2026-08-14-foldable-support.md`). Each phase ships as its own PR.

**Goal:** Give KyPost a good experience on every window size, from a small phone to a Googlebook
desktop window. Each size gets the right layout, folds behave correctly, and keyboard and mouse work
the way desktop users expect.

**Architecture:** Android Views, as today. Each screen stays its own Activity, and the two-pane
layouts stay on Activity Embedding (`res/xml/split_config.xml`). Layout tiers come from resource
qualifiers. Fold and hinge awareness uses `androidx.window`, which the app already depends on (1.5.1).
No new dependencies.

**Spec:** extends `docs/superpowers/specs/2026-08-14-foldable-support-design.md`. This plan revisits
two items that spec ruled out of scope: the `w840dp` tier and desktop-class layouts.

**Decisions (2026-10-15):**
- Not pursuing Google Play's Apps Experience Program (AEP), and so no Jetpack Compose migration.
- Keep the current Activities and Activity Embedding.
- Add a "Follow system" theme.
- No screenshot tests for now.

---

## Global Constraints

1. **No `android:configChanges`.** A resize, fold or theme change recreates the Activity, and the
   recreate picks up the new resources.
2. **Saved-state Bundles hold identifiers and view positions only.** Never message bodies, draft text
   or contact PII; those stay in `ComposeDraftCache` and `ContactEditDraftCache`.
3. **Close-and-lock wins over layout.** A lock event lands the user in the Inbox with default state.
   Never restore deeper context past a lock.
4. **`LockedActivity` stays the base of every screen.** `FLAG_SECURE`, overlay hiding, the wipe
   tripwire and the lock redirect do not move.
5. **The WebView settings do not change**, except for the zoom settings in Phase 3. The email body
   keeps `javaScriptEnabled = false`.
6. **Palettes stay numerically identical to the web app** (STYLE_GUIDE intro). STYLE_GUIDE §6 ("What
   to keep native") still applies.
7. **Behaviour that unit tests can't cover gets an instrumented test.** Size-dependent layouts are
   tested on the existing emulator matrix, plus a tablet-sized and a foldable AVD wherever a phase
   says so.

---

## Layout tiers

| Tier | Width | Qualifier | Typical device |
| --- | --- | --- | --- |
| **C** | < 600dp | `layout/` | Small and large phones, fold cover screen |
| **M** | 600–839dp | `layout-w600dp/` (exists) | Phone landscape, fold inner screen, tablet portrait |
| **E** | 840–1199dp | `layout-w840dp/` (new, only where a screen needs it) | Fold inner screen landscape, tablet landscape |
| **L** | ≥ 1200dp | `layout-w1200dp/` (new, only where a screen needs it) | Large tablet, Googlebook at full screen |

On top of the width tier, the layouts respond to three device states:

- **Landscape phone (HC):** height < 480dp.
- **Book:** fold half-open, hinge vertical.
- **Hinge:** the fold separates the screen into two parts.

| Surface | C | M | E | L | Fold states |
| --- | --- | --- | --- | --- | --- |
| **Navigation** | Bottom bar | Rail (today) | Rail | Rail | — |
| **Inbox → message** | List, then message | Same as C | List \| message, 0.4 split | List pane fixed ~400dp \| message; reading column ≤ 720dp | Book: split on the hinge |
| **Compose** | Full screen | Fields ≤ 720dp, centred (existing `w600dp` variant) | Same as M | Same as M | Hinge: toolbar inside one half |
| **Contacts → detail/edit** | Stacked | Same as C | List \| detail | Same as E | Book: split on the hinge |
| **Settings and sub-screens** | Single column | Column ≤ 600dp, centred | Same as M | Same as M | — |
| **Unlock, MFA, pairing, enrolment** | Centred task | Card ≤ 480dp, centred | Same as M | Same as M | Hinge: PIN pad inside one half |
| **Bottom sheets** (`AddressBookSheet`) | Full width | ≤ 640dp | Same as M | Same as M | — |
| **HC** | — | Rail; no fixed footers that eat the height | — | — | — |

**The two-pane breakpoint moves from 800dp to 840dp** (`split_config.xml:14`, `:27`), to match the
Material window size classes. Windows from 800 to 839dp go back to one pane.

---

## Phase 1 — Groundwork

- [ ] **Follow system theme:**
  - Add `"Follow system"` to `THEME_OPTIONS`. It resolves to Busnes Light or Busnes Dark from
    `Configuration.uiMode`. A `uiMode` change already recreates the Activity, so no new plumbing is
    needed.
  - Make it the `DEFAULT_THEME` (`AppTheme.kt:30`).
  - **Behaviour change:** `currentTheme` falls back to `DEFAULT_THEME` when no theme is saved
    (`AppTheme.kt:104`). Users who never picked a theme therefore switch from Busnes Light to
    following the system. Users who picked a theme keep it.
  - **Tests:** a JVM test of the resolver; an instrumented test that toggles night mode and checks
    the repaint.
- [ ] **Predictive back:**
  - Add `android:enableOnBackInvokedCallback="true"` to the `<application>`. No Activity overrides
    `onBackPressed`. Compose and Unlock already use `onBackPressedDispatcher`, so the flag is safe.
  - **Test:** the existing discard-confirm test still passes on API 34 and 36.
- [ ] **Themed icon:** add a `<monochrome>` layer to `mipmap-anydpi/ic_launcher*.xml`.
- [ ] **Breakpoint:** change `splitMinWidthDp` from 800 to 840. Update the Inbox-rail and split
      instrumented tests that assume 800.

## Phase 2 — Layouts for every tier, and foldables

- [ ] **Capped-width containers:**
  - Settings and its sub-screens: column ≤ 600dp.
  - Unlock, MFA, pairing and enrolment: card ≤ 480dp.
  - Message reading column: ≤ 720dp.
  - Compose: check the existing `w600dp` variant against the table.

  The layouts have no ConstraintLayout and gain none. Use a centred, fixed-width container in `-w600dp`
  variants, or a `dimen` from `values-w600dp`.
- [ ] **L tier:** fix the Inbox and Contacts list pane at ~400dp, so the message or detail pane gets
      the extra width, using a `SplitAttributes` calculator in `ui/SplitInitializer.kt`.
- [ ] **Book posture:** in the same calculator, split on the hinge whenever a separating
      `FoldingFeature` is present, and use 0.4 otherwise.
      **Unverified:** whether `split_config.xml` can express this on its own. Assume code.
- [ ] **Hinge on single-pane screens:** where `FoldingFeature.isSeparating`, keep the Compose toolbar
      and the Unlock PIN pad inside one half. This needs a small helper on `WindowInfoTracker`, used
      by those two screens only.
- [ ] **Landscape phone:** check every screen at 360dp height. Remove or allow scrolling for any fixed
      footer that hides content.
- [ ] **Sheets:** cap `AddressBookSheet` at 640dp.
- [ ] **Verify** on the existing phone emulators, a tablet AVD and a `pixel_fold` AVD, using the
      transition tables (Class A: live resize; Class B: close-and-lock) from the foldable spec. Record
      the results in this file, the way that spec does.

## Phase 3 — Keyboard and mouse

- [ ] **Shortcuts:** handle these in `onKeyShortcut` and list them in `onProvideKeyboardShortcuts`, so
      they appear in the system Keyboard Shortcuts Helper.

  | Keys | Action |
  | --- | --- |
  | Ctrl+N | Compose |
  | Ctrl+R | Reply |
  | Ctrl+Shift+R | Reply all |
  | Ctrl+F | Search, if search exists |
  | Delete | Delete |
  | J / K | Next / previous message |

- [ ] **Send:** Ctrl+Enter sends from Compose. Catch it in `dispatchKeyEvent` before
      `RichHtmlEditorWebView` consumes it.
- [ ] **Escape:** Esc closes dialogs and sheets, and goes back from the detail pane.
      **Unverified:** whether the platform already maps Escape to back on these API levels. Test it
      before adding code.
- [ ] **Right-click menus:** inbox rows offer archive, delete and mark read/unread; contact rows offer
      open, edit and delete. Use `setOnContextClickListener` with the same actions as the existing
      menus.
- [ ] **Hover and focus:** `item_email.xml` is a plain `androidx.cardview` with no state feedback.
      Give it a ripple foreground with hover and focus states, and do the same for contact rows and
      chips. Every focusable view shows a visible focus ring, and the tab order is logical on every
      screen.
- [ ] **Touch targets:** every target is at least 48dp. Audit `Widget.KyPost.IconOnlyChip`.
- [ ] **Zoom:** Ctrl+= / Ctrl+− / Ctrl+scroll / pinch zoom the message body, using the WebView's own
      zoom settings. JavaScript stays off.
- [ ] **Tests:** an instrumented test for each shortcut, for Ctrl+Enter, and for one right-click menu.

## Phase 4 — Desktop (Googlebook)

- [ ] **Freeform resizing:** drag a window live from C to L on a desktop-windowing emulator. Every
      screen survives the recreates without losing state (Phase 2 constraints).
- [ ] **Scrollbars:** `android:scrollbars="vertical"` on the lists and the message body.
- [ ] **Mouse pointer:** a hand cursor (`PointerIcon.TYPE_HAND`) on clickable rows and chips.
- [ ] **Optional — Compose in a new window:** needs its own design first. `ComposeDraftCache` holds a
      single draft, and the lock screen is `singleInstance`; both conflict with two Compose windows.
- [ ] **Optional — drag attachments in and out:** needs its own design first. It touches
      `EphemeralAttachmentProvider` and the download ledger. The foldable spec ruled it out of scope.

---

## Dropped, with reasons

- **AEP enrolment, the Compose migration, Material 3, passkey pairing, Restore Credentials:** dropped
  2026-10-15 along with the AEP goal. Passkeys would still make pairing harder to phish; consider them
  as separate security work.
- **Screenshot tests:** deferred. Roborazzi needs Robolectric, and `app/src/test/AGENTS.md` keeps the
  JVM tests free of the Android framework. Revisit with its own source set, or with an on-device tool.
