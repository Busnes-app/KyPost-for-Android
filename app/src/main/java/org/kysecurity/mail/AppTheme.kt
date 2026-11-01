package org.kysecurity.mail

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
import android.content.res.Configuration
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.ColorDrawable
import android.graphics.drawable.GradientDrawable
import android.text.SpannableString
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import android.widget.CompoundButton
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.RadioButton
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat
import com.google.android.material.floatingactionbutton.FloatingActionButton

const val THEME_STORAGE_KEY = "kypost-theme"
const val THEME_MODE_STORAGE_KEY = "kypost-theme-mode"

/** Which half of the pair paints. [SYSTEM] follows the system night mode. */
enum class ThemeMode(val storageValue: String) { SYSTEM("system"), LIGHT("light"), DARK("dark") }

data class ThemePalette(
    val bg: String,
    val panel: String,
    val ink: String,
    val inkStrong: String,
    val accent: String,
    val line: String,
    // Avatar gradient stops - mirror web's ThemeVars newEmailStart/End/Border.
    val avatarGradientStart: String,
    val avatarGradientEnd: String,
    val avatarBorder: String,
    // Status colours, separate from the accent (ky-ui 0.8.0). Each half pairs them with its own
    // soft tint, [statusSoft]; ThemePaletteTableTest holds them to ky-ui's status-colour gate.
    val danger: String,
    val warning: String,
    val success: String,
)

/** A light half and a dark half under one name (ky-ui `THEME_PAIRS`). [id] is what is saved. */
data class ThemePair(val id: String, val name: String, val light: ThemePalette, val dark: ThemePalette)

data class ThemeChoice(val pair: ThemePair, val mode: ThemeMode)

// ky-ui tokens.css `--ky-{danger,warning,success}-{light,dark}`: the defaults for a half that
// names no status colour of its own. Danger is a cool crimson, never the accent.
private const val DANGER_LIGHT = "#a8174e"
private const val DANGER_DARK = "#ff8fb1"
private const val WARNING_LIGHT = "#7a5f00"
private const val WARNING_DARK = "#ffd25e"
private const val SUCCESS_LIGHT = "#267442"
private const val SUCCESS_DARK = "#86efac"

/** `--ky-*-soft`: the status mixed this far into `panel`. */
internal const val STATUS_SOFT_PERCENT = 12

private fun lightHalf(
    bg: String, panel: String, ink: String, inkStrong: String, accent: String, line: String,
    avatarStart: String, avatarEnd: String, avatarBorder: String,
    danger: String = DANGER_LIGHT, warning: String = WARNING_LIGHT, success: String = SUCCESS_LIGHT,
) = ThemePalette(bg, panel, ink, inkStrong, accent, line, avatarStart, avatarEnd, avatarBorder, danger, warning, success)

private fun darkHalf(
    bg: String, panel: String, ink: String, inkStrong: String, accent: String, line: String,
    avatarStart: String, avatarEnd: String, avatarBorder: String,
    danger: String = DANGER_DARK, warning: String = WARNING_DARK, success: String = SUCCESS_DARK,
) = ThemePalette(bg, panel, ink, inkStrong, accent, line, avatarStart, avatarEnd, avatarBorder, danger, warning, success)

// Values are ky-ui src/themes.js THEME_PALETTES and tokens.css (Busnes); keep them identical.
// Busnes `line` is the handoff's control border composited onto `panel` — blend() drops alpha,
// so a translucent line would paint applyEmptyStateBackground's dashed border near-black on cream.
// Avatar stops are Android's own (STYLE_GUIDE.md §1); buttonText falls out of readableOn(accent).
val THEME_PAIRS = listOf(
    ThemePair(
        "busnes-pair", "Busnes",
        lightHalf("#f8f6f0", "#ffffff", "#566461", "#182326", "#bf3f18", "#cccfcf", "#bf3f18", "#e65124", "#bf3f18"),
        darkHalf("#182326", "#1f2b2e", "#b3bcb8", "#f2efe8", "#f5865f", "#525a5b", "#f5865f", "#f26a3d", "#f5865f"),
    ),
    ThemePair(
        "matter-pair", "Matter",
        lightHalf("#f5efe5", "#fff8ee", "#4c3d32", "#2d1f15", "#805a39", "#d4c7b5", "#805a39", "#9a7450", "#805a39"),
        darkHalf("#1d1b19", "#292725", "#cfc6bb", "#f0e9df", "#c29a72", "#45403a", "#c29a72", "#9a7450", "#8f6b4a"),
    ),
    ThemePair(
        "ocean-pair", "Ocean",
        lightHalf("#f7f9fb", "#ffffff", "#2e4c63", "#163246", "#1d5fa6", "#c7d6df", "#1d5fa6", "#2f7fb0", "#1d5fa6"),
        darkHalf("#0f1b24", "#152a36", "#b8d8e8", "#e0f2fb", "#6aa8e8", "#2f5567", "#6aa8e8", "#4f91a6", "#4f91a6"),
    ),
    // Teal success: the shared green sits too close to Forest's green accent.
    ThemePair(
        "forest-pair", "Forest",
        lightHalf("#f3f6ef", "#fcfdf9", "#435342", "#203322", "#4b6b37", "#c5d0bc", "#4b6b37", "#6f8d5a", "#4b6b37", success = "#00737a"),
        darkHalf("#142018", "#1f2f24", "#c7dbc7", "#e3f0df", "#8faa74", "#4f694f", "#8faa74", "#6f8d5a", "#6f8d5a", success = "#6ee0d0"),
    ),
    ThemePair(
        "ky-pair", "Ky",
        lightHalf("#eef2f6", "#ffffff", "#475569", "#0f172a", "#08758b", "#c2cdd8", "#08758b", "#10b981", "#059669"),
        darkHalf("#10161e", "#1b2530", "#afbdca", "#e2e8f0", "#6fc9cc", "#34414d", "#6fc9cc", "#10b981", "#0e9668"),
    ),
    // Nord Dark keeps its own base danger and success.
    ThemePair(
        "nord-pair", "Nord",
        lightHalf("#eceff4", "#ffffff", "#4c566a", "#2e3440", "#4a6a94", "#c5cdd9", "#4a6a94", "#5e81ac", "#4a6a94"),
        darkHalf("#2e3440", "#3b4252", "#d8dee9", "#eceff4", "#88c0d0", "#4c566a", "#88c0d0", "#81a1c1", "#5e81ac", danger = "#ecc4c8", success = "#bcd4aa"),
    ),
)

/** Fallback when nothing is saved, and when a saved theme is no longer offered. */
val DEFAULT_THEME_CHOICE = ThemeChoice(THEME_PAIRS.first(), ThemeMode.SYSTEM)

private fun pair(id: String) = THEME_PAIRS.first { it.id == id }

/** Names saved before the pairs. A surviving half keeps the mode its choice fixed; every other
 *  retired palette (Tropics, Coffee, Sky, ...) is absent and resets to [DEFAULT_THEME_CHOICE]. */
internal val LEGACY_THEME_NAMES: Map<String, ThemeChoice> = mapOf(
    "Follow system" to DEFAULT_THEME_CHOICE,
    "Busnes Light" to ThemeChoice(pair("busnes-pair"), ThemeMode.LIGHT),
    "Busnes Dark" to ThemeChoice(pair("busnes-pair"), ThemeMode.DARK),
    "Light Matter" to ThemeChoice(pair("matter-pair"), ThemeMode.LIGHT),
    "Dark Matter" to ThemeChoice(pair("matter-pair"), ThemeMode.DARK),
    "White Cliffs" to ThemeChoice(pair("ocean-pair"), ThemeMode.LIGHT),
    "Ocean" to ThemeChoice(pair("ocean-pair"), ThemeMode.DARK),
    "Forest" to ThemeChoice(pair("forest-pair"), ThemeMode.DARK),
    "Polished Ky" to ThemeChoice(pair("ky-pair"), ThemeMode.LIGHT),
    "Patina Ky" to ThemeChoice(pair("ky-pair"), ThemeMode.DARK),
)

/** Reads both stored values. A legacy name never had a mode key, so its own mode wins. */
internal fun resolveThemeChoice(savedTheme: String?, savedMode: String?): ThemeChoice {
    val pair = THEME_PAIRS.firstOrNull { it.id == savedTheme }
        ?: return LEGACY_THEME_NAMES[savedTheme] ?: DEFAULT_THEME_CHOICE
    return ThemeChoice(pair, ThemeMode.values().firstOrNull { it.storageValue == savedMode } ?: ThemeMode.SYSTEM)
}

private fun settings(context: Context) =
    context.getSharedPreferences("org.kysecurity.mail.settings", Context.MODE_PRIVATE)

fun getStoredThemeChoice(context: Context): ThemeChoice {
    val prefs = settings(context)
    return resolveThemeChoice(prefs.getString(THEME_STORAGE_KEY, null), prefs.getString(THEME_MODE_STORAGE_KEY, null))
}

/** Always writes both keys, so a legacy name is replaced the first time anything is chosen. */
fun saveThemeChoice(context: Context, choice: ThemeChoice) {
    settings(context).edit()
        .putString(THEME_STORAGE_KEY, choice.pair.id)
        .putString(THEME_MODE_STORAGE_KEY, choice.mode.storageValue)
        .apply()
}

fun getStoredThemePalette(context: Context): ThemePalette {
    return themePaletteFor(getStoredThemeChoice(context), isSystemDark(context))
}

fun isSystemDark(context: Context): Boolean =
    (context.resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES

/** The half [choice] paints with; [systemDark] matters only for [ThemeMode.SYSTEM]. */
fun themePaletteFor(choice: ThemeChoice, systemDark: Boolean): ThemePalette {
    val dark = when (choice.mode) {
        ThemeMode.SYSTEM -> systemDark
        ThemeMode.LIGHT -> false
        ThemeMode.DARK -> true
    }
    return if (dark) choice.pair.dark else choice.pair.light
}

/** CSS `color-mix(in srgb, [color] [percent]%, [base])` on `#rrggbb`; pure, so unit-testable. */
internal fun mixHex(color: String, percent: Int, base: String): String {
    fun channel(hex: String, i: Int) = hex.substring(1 + 2 * i, 3 + 2 * i).toInt(16)
    return "#" + (0..2).joinToString("") { i ->
        Math.round(channel(color, i) * percent / 100.0 + channel(base, i) * (1 - percent / 100.0)).toInt()
            .toString(16).padStart(2, '0')
    }
}

/** `--ky-{status}-soft` for this half: the pill fill under status-coloured text. */
internal fun ThemePalette.statusSoft(status: String): String = mixHex(status, STATUS_SOFT_PERCENT, panel)

fun applyThemeToActivity(activity: Activity) {
    val palette = getStoredThemePalette(activity)
    val bgColor = Color.parseColor(palette.bg)

    // Bars are transparent under edge-to-edge: the window background shows behind the status bar.
    activity.window.decorView.setBackgroundColor(bgColor)
    WindowInsetsControllerCompat(activity.window, activity.window.decorView).run {
        isAppearanceLightStatusBars = readableOn(bgColor) == Color.BLACK
        // ponytail: bg, not panel — the bottom bar's panel background only reaches under the
        // navigation bar on the inbox; every other screen shows bg there.
        isAppearanceLightNavigationBars = readableOn(bgColor) == Color.BLACK
    }

    if (activity is AppCompatActivity) {
        activity.supportActionBar?.setBackgroundDrawable(ColorDrawable(bgColor))
        activity.supportActionBar?.title = styledTitle(activity.title?.toString().orEmpty(), readableOn(bgColor))
    }

    // The overflow icon is outside the content tree and only exists after onCreateOptionsMenu.
    activity.window.decorView.post {
        tintOverflowIcon(activity, readableOn(bgColor))
    }

    val root: View = activity.findViewById(android.R.id.content)
    root.setBackgroundColor(bgColor)
    applyThemeToViewTree(root, palette)
}

/** Sets the action-bar title and repaints just its text color for the active palette, without
 *  re-theming the whole view tree (which would clobber custom backgrounds like the tab bar). */
fun applyThemedTitle(activity: Activity, title: CharSequence) {
    activity.title = title
    if (activity is AppCompatActivity) {
        val bg = Color.parseColor(getStoredThemePalette(activity).bg)
        activity.supportActionBar?.title = styledTitle(title.toString(), readableOn(bg))
    }
}

fun applyCheckBoxTheme(context: Context, checkBox: CompoundButton) {
    val palette = getStoredThemePalette(context)
    checkBox.setTextColor(Color.parseColor(palette.inkStrong))
    checkBox.buttonTintList = ColorStateList.valueOf(Color.parseColor(palette.accent))
}

fun applyKyPostTopBar(activity: Activity, subtitle: CharSequence) {
    applyThemedTitle(activity, activity.getString(R.string.app_name))
    if (activity is AppCompatActivity) {
        val palette = getStoredThemePalette(activity)
        val bg = Color.parseColor(palette.bg)
        val accent = Color.parseColor(palette.accent)
        val ink = Color.parseColor(palette.ink)
        activity.supportActionBar?.run {
            setBackgroundDrawable(ColorDrawable(bg))
            setDisplayShowHomeEnabled(false)
            setDisplayUseLogoEnabled(false)
            setDisplayShowTitleEnabled(false)
            setDisplayShowCustomEnabled(true)
            customView = LinearLayout(activity).apply {
                gravity = Gravity.CENTER_VERTICAL
                orientation = LinearLayout.HORIZONTAL
                setPadding(0, 4 * density.toInt(), 0, 4 * density.toInt())
                addView(ImageView(activity).apply {
                    setImageResource(R.mipmap.ic_launcher_foreground)
                    setBackgroundResource(R.drawable.rounded_image_clip)
                    clipToOutline = true
                    scaleType = ImageView.ScaleType.CENTER_INSIDE
                }, LinearLayout.LayoutParams((56 * density).toInt(), (56 * density).toInt()))
                addView(LinearLayout(activity).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding((12 * density).toInt(), 0, 0, 0)
                    addView(TextView(activity).apply {
                        text = activity.getString(R.string.app_name)
                        textSize = 32f
                        typeface = Typeface.DEFAULT_BOLD
                        setTextColor(accent)
                        includeFontPadding = false
                    })
                    addView(TextView(activity).apply {
                        text = subtitle
                        textSize = 12f
                        typeface = Typeface.create(Typeface.MONOSPACE, Typeface.BOLD)
                        letterSpacing = 0.18f
                        setTextColor(ink)
                        includeFontPadding = false
                        isAllCaps = true
                    })
                })
            }
        }
    }
}

/** The system-bar bottom inset the keyboard does not already cover. Android 14 (seen on a moto
 *  g play 2024) reports systemBars().bottom as the whole keyboard height while it is up; padding
 *  by that on top of [applyTopInsetWithHeader]'s IME padding stretched the bottom bar to twice
 *  the keyboard and squeezed Compose to a sliver. */
fun barBottomInset(insets: WindowInsetsCompat): Int = barBottomInset(
    insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom,
    insets.getInsets(WindowInsetsCompat.Type.ime()).bottom,
)

internal fun barBottomInset(systemBarsBottom: Int, imeBottom: Int): Int =
    (systemBarsBottom - imeBottom).coerceAtLeast(0)

/** Pads the view's bottom by the system navigation-bar inset so edge-to-edge content (e.g. the
 *  bottom navigation bar) clears the gesture/nav area. */
fun applyBottomInset(view: View) {
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bottomInset = barBottomInset(insets)
        v.setPadding(v.paddingLeft, v.paddingTop, v.paddingRight, basePaddingBottom + bottomInset)
        insets
    }
    ViewCompat.requestApplyInsets(view)
}

/** Rail equivalent of [applyBottomInset]: a full-height rail on the end edge also needs top and
 *  end insets. */
fun applyRailInsets(activity: Activity, view: View) {
    val basePaddingEnd = view.paddingEnd
    val basePaddingTop = view.paddingTop
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
        val endInset = if (v.layoutDirection == View.LAYOUT_DIRECTION_RTL) bars.left else bars.right
        v.setPaddingRelative(
            v.paddingStart,
            basePaddingTop + bars.top + actionBarSize(activity),
            basePaddingEnd + endInset,
            basePaddingBottom + barBottomInset(insets),
        )
        insets
    }
    ViewCompat.requestApplyInsets(view)
}

fun applyTopInsetWithHeader(activity: Activity, root: View) {
    val basePaddingLeft = root.paddingLeft
    val basePaddingTop = root.paddingTop
    val basePaddingRight = root.paddingRight
    val basePaddingBottom = root.paddingBottom

    ViewCompat.setOnApplyWindowInsetsListener(root) { view, insets ->
        val topInset = insets.getInsets(WindowInsetsCompat.Type.systemBars()).top
        // targetSdk 36 edge-to-edge: adjustResize no longer shrinks the window, so pad by the IME.
        val imeInset = insets.getInsets(WindowInsetsCompat.Type.ime()).bottom
        view.setPadding(
            basePaddingLeft,
            basePaddingTop + topInset + actionBarSize(activity),
            basePaddingRight,
            basePaddingBottom + imeInset,
        )
        insets
    }
    ViewCompat.requestApplyInsets(root)
}

fun applyPrimaryNavigationTheme(context: Context, nav: com.google.android.material.navigation.NavigationBarView) {
    val palette = getStoredThemePalette(context)
    val panel = Color.parseColor(palette.panel)
    val ink = Color.parseColor(palette.ink)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val accent = Color.parseColor(palette.accent)

    nav.backgroundTintList = null
    nav.setBackgroundColor(panel)
    val states = arrayOf(
        intArrayOf(android.R.attr.state_checked),
        intArrayOf(),
    )
    val colors = intArrayOf(inkStrong, ink)
    val list = ColorStateList(states, colors)
    nav.itemTextColor = list
    nav.itemIconTintList = list
    nav.itemRippleColor = ColorStateList.valueOf(withAlpha(accent, 0.20f))
    nav.itemActiveIndicatorColor = ColorStateList.valueOf(withAlpha(accent, 0.30f))
}

fun applyPrimaryButtonTheme(context: Context, button: Button) {
    val palette = getStoredThemePalette(context)
    button.backgroundTintList = null
    button.background = buttonBackground(palette)
    button.setTextColor(readableOn(Color.parseColor(palette.accent)))
    applyButtonPadding(button)
}

fun applyIconButtonTheme(context: Context, button: android.widget.ImageButton) {
    val palette = getStoredThemePalette(context)
    button.imageTintList = ColorStateList.valueOf(Color.parseColor(palette.inkStrong))
}

/** Transparent fill + 1dp `line` stroke, `inkStrong` text — mirrors web's `.notifications-ghost`.
 *  Use for secondary actions that shouldn't compete with a primary button (e.g. "Cancel"). */
fun applyGhostButtonTheme(context: Context, button: Button) {
    val palette = getStoredThemePalette(context)
    button.backgroundTintList = null
    button.background = ghostButtonBackground(palette)
    button.setTextColor(Color.parseColor(palette.inkStrong))
    applyButtonPadding(button)
}

/** What a status means. Never shown by colour alone: callers pair it with a word, and a dot or icon. */
enum class StatusTone { NEUTRAL, SUCCESS, WARNING, DANGER }

/** The active half's status colour for [tone]; [StatusTone.NEUTRAL] is `ink`. */
internal fun ThemePalette.statusColor(tone: StatusTone): String = when (tone) {
    StatusTone.NEUTRAL -> ink
    StatusTone.SUCCESS -> success
    StatusTone.WARNING -> warning
    StatusTone.DANGER -> danger
}

/** 1dp danger stroke over the half's danger-soft fill, danger text — mirrors web's
 *  `.users-action-danger` / `.contacts-action-danger`. Destructive actions only, never the accent. */
fun applyDangerButtonTheme(context: Context, button: Button) {
    val palette = getStoredThemePalette(context)
    val danger = Color.parseColor(palette.danger)
    button.backgroundTintList = null
    button.background = dangerButtonBackground(Color.parseColor(palette.statusSoft(palette.danger)), danger)
    button.setTextColor(danger)
    applyButtonPadding(button)
}

/** Warning callout: the danger-button stroke+fill shape in the half's warning colours, with a
 *  leading warning dot so the state never rests on colour alone. */
fun applyWarningCalloutTheme(context: Context, textView: TextView) {
    val palette = getStoredThemePalette(context)
    val warning = Color.parseColor(palette.warning)
    textView.background = warningCalloutBackground(Color.parseColor(palette.statusSoft(palette.warning)), warning)
    textView.setTextColor(warning)
    setLeadingStatusDot(context, textView, warning)
}

/** Status text, e.g. an error line: the tone's colour plus a leading dot. */
fun applyStatusText(context: Context, textView: TextView, tone: StatusTone) {
    val color = Color.parseColor(getStoredThemePalette(context).statusColor(tone))
    textView.setTextColor(color)
    setLeadingStatusDot(context, textView, color)
}

private fun setLeadingStatusDot(context: Context, textView: TextView, color: Int) {
    textView.compoundDrawablePadding = dpToPx(8)
    textView.setCompoundDrawablesRelativeWithIntrinsicBounds(unreadDotDrawable(context, sizeDp = 7, color = color), null, null, null)
}

/** Success chip state. Pass [animate] only from the tap; per-bind recycled rows stay instant. */
fun applySuccessChipTheme(
    context: Context,
    chip: com.google.android.material.chip.Chip,
    animate: Boolean = false,
) {
    val palette = getStoredThemePalette(context)
    val toBg = Color.parseColor(palette.statusSoft(palette.success))
    val toStroke = Color.parseColor(palette.success)
    val toText = toStroke
    chip.chipStrokeWidth = 1f * context.resources.displayMetrics.density
    if (animate) {
        animateChipColorTransition(
            chip = chip,
            fromBg = chip.chipBackgroundColor?.defaultColor ?: toBg,
            toBg = toBg,
            fromStroke = chip.chipStrokeColor?.defaultColor ?: toStroke,
            toStroke = toStroke,
            fromText = chip.textColors?.defaultColor ?: toText,
            toText = toText,
        )
    } else {
        chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(toBg)
        chip.chipStrokeColor = android.content.res.ColorStateList.valueOf(toStroke)
        chip.setTextColor(toText)
    }
}

/** 120ms cross-fade (STYLE_GUIDE.md §5); not used for Chip's own checked state machine. */
fun animateChipColorTransition(
    chip: com.google.android.material.chip.Chip,
    fromBg: Int,
    toBg: Int,
    fromStroke: Int,
    toStroke: Int,
    fromText: Int,
    toText: Int,
    durationMs: Long = 120L,
) {
    val evaluator = android.animation.ArgbEvaluator()
    android.animation.ValueAnimator.ofFloat(0f, 1f).apply {
        duration = durationMs
        interpolator = androidx.interpolator.view.animation.FastOutSlowInInterpolator()
        addUpdateListener { animator ->
            val t = animator.animatedFraction
            chip.chipBackgroundColor = android.content.res.ColorStateList.valueOf(
                evaluator.evaluate(t, fromBg, toBg) as Int,
            )
            chip.chipStrokeColor = android.content.res.ColorStateList.valueOf(
                evaluator.evaluate(t, fromStroke, toStroke) as Int,
            )
            chip.setTextColor(evaluator.evaluate(t, fromText, toText) as Int)
        }
        start()
    }
}

/** Small uppercase section label - group headers only, not body copy or per-field captions. */
fun applySectionEyebrowLabel(context: Context, textView: TextView) {
    val palette = getStoredThemePalette(context)
    val inkStrong = Color.parseColor(palette.inkStrong)
    textView.isAllCaps = true
    textView.letterSpacing = 0.08f
    textView.textSize = 11f
    textView.setTextColor(withAlpha(inkStrong, 0.72f))
}

/** Inactive fill must be an opaque `panel`: ChipDrawable paints colorSurface underneath it. */
fun applyPillChipTheme(context: Context, chip: com.google.android.material.chip.Chip) {
    val palette = getStoredThemePalette(context)
    val panel = Color.parseColor(palette.panel)
    val line = Color.parseColor(palette.line)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val accent = Color.parseColor(palette.accent)
    val onAccent = readableOn(accent)

    val checkedState = intArrayOf(android.R.attr.state_checked)
    val uncheckedState = intArrayOf(-android.R.attr.state_checked)
    val states = arrayOf(checkedState, uncheckedState)

    val contentColors = ColorStateList(states, intArrayOf(onAccent, inkStrong))

    chip.chipBackgroundColor = ColorStateList(states, intArrayOf(accent, panel))
    chip.setTextColor(contentColors)
    chip.chipStrokeColor = ColorStateList(states, intArrayOf(accent, line))
    chip.chipStrokeWidth = 1f * density
    chip.rippleColor = ColorStateList.valueOf(withAlpha(accent, 0.22f))
    chip.checkedIcon = null
    // Only tint, never clear: callers that pre-set `app:chipIcon` in XML want it recolored.
    if (chip.chipIcon != null) {
        chip.chipIconTint = contentColors
    }
}

/** Bold or regular weight of the view's own face. `setTypeface(current, NORMAL)` keeps a face that is
 *  already bold, so the style is derived from a base instead. The base is any face this did not set
 *  itself: Space Grotesk is downloadable and AppCompat swaps it in after inflation. */
fun TextView.setBold(bold: Boolean) {
    val applied = getTag(R.id.tag_bold_applied_face)
    val base = (getTag(R.id.tag_bold_base_face) as? Typeface)?.takeIf { typeface === applied } ?: typeface
    val face = Typeface.create(base, if (bold) Typeface.BOLD else Typeface.NORMAL)
    setTag(R.id.tag_bold_base_face, base)
    setTag(R.id.tag_bold_applied_face, face)
    typeface = face
}

/** Defaults to `accent`; pass a contrasting [color] when placing it on an accent-filled surface. */
fun unreadDotDrawable(context: Context, sizeDp: Int = 8, color: Int? = null): GradientDrawable {
    val palette = getStoredThemePalette(context)
    val sizePx = (sizeDp * density).toInt()
    return GradientDrawable().apply {
        shape = GradientDrawable.OVAL
        setColor(color ?: Color.parseColor(palette.accent))
        setSize(sizePx, sizePx)
    }
}

/** Status badge + dot: a status tone paints the half's status colour over its soft tint;
 *  [StatusTone.NEUTRAL] is theme line/panel/ink. */
fun applyStatusBadgeTheme(context: Context, chip: com.google.android.material.chip.Chip, tone: StatusTone) {
    val palette = getStoredThemePalette(context)
    val border: Int
    val text: Int
    val fill: Int
    if (tone == StatusTone.NEUTRAL) {
        border = Color.parseColor(palette.line)
        text = Color.parseColor(palette.ink)
        fill = Color.parseColor(palette.panel)
    } else {
        val status = palette.statusColor(tone)
        border = Color.parseColor(status)
        text = border
        fill = Color.parseColor(palette.statusSoft(status))
    }
    chip.isCheckable = false
    chip.isClickable = false
    chip.isFocusable = false
    chip.chipBackgroundColor = ColorStateList.valueOf(fill)
    chip.chipStrokeColor = ColorStateList.valueOf(border)
    chip.chipStrokeWidth = 1f * density
    chip.setTextColor(text)
    chip.textSize = 12f
    chip.chipIcon = unreadDotDrawable(context, sizeDp = 7, color = border)
    chip.chipIconTint = null
    chip.chipIconSize = 7f * density
    chip.isChipIconVisible = true
}

/** Circular, two-stop gradient avatar with initials — mirrors web's `.users-avatar` /
 *  `.contacts-avatar`. [sizeDp] is 34dp for list rows, 52dp for a detail header per the guide. */
fun bindAvatar(context: Context, view: TextView, displayName: String, sizeDp: Int) {
    val palette = getStoredThemePalette(context)
    val accent = Color.parseColor(palette.accent)
    view.text = initialsOf(displayName)
    view.gravity = android.view.Gravity.CENTER
    view.setTextColor(readableOn(accent))
    view.background = GradientDrawable(
        GradientDrawable.Orientation.TOP_BOTTOM,
        intArrayOf(Color.parseColor(palette.avatarGradientStart), Color.parseColor(palette.avatarGradientEnd)),
    ).apply {
        shape = GradientDrawable.OVAL
        setStroke((1 * density).toInt(), Color.parseColor(palette.avatarBorder))
    }
    val sizePx = (sizeDp * density).toInt()
    view.layoutParams = (view.layoutParams ?: ViewGroup.LayoutParams(sizePx, sizePx)).apply {
        width = sizePx
        height = sizePx
    }
}

/** First letter of the first and last whitespace-separated word ("Ada Lovelace" -> "AL",
 *  "Cher" -> "C"), mirroring the initials web derives for the same avatar component. */
internal fun initialsOf(displayName: String): String {
    val words = displayName.trim().split(Regex("\\s+")).filter { it.isNotBlank() }
    return when {
        words.isEmpty() -> ""
        words.size == 1 -> words[0].take(1).uppercase()
        else -> (words.first().take(1) + words.last().take(1)).uppercase()
    }
}

/** Dashed, accent-tinted-line, 10dp-radius background for a list's "nothing here yet" message —
 *  mirrors web's `.contacts-empty`. */
fun applyEmptyStateBackground(context: Context, view: View) {
    val palette = getStoredThemePalette(context)
    view.background = GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setStroke(
            (1.5f * density).toInt(),
            blend(Color.parseColor(palette.line), Color.parseColor(palette.accent), 0.12f),
            6f * density,
            4f * density,
        )
    }
    val padH = (16 * density).toInt()
    view.setPadding(padH, padH, padH, padH)
}

// Wraps raw ttf bytes into a @font-face CSS block. Pure/testable — split out from
// [ibmPlexMonoFontFaceCss] so the encoding logic has a JVM unit test with no Android asset I/O.
internal fun buildMonoFontFaceCss(fontBytes: ByteArray): String {
    val base64 = java.util.Base64.getEncoder().encodeToString(fontBytes)
    return "@font-face{font-family:'IBM Plex Mono';font-style:normal;font-weight:400;" +
        "src:url(data:font/ttf;base64,$base64) format('truetype');}"
}

private val monoFontFaceCssLock = Any()
@Volatile private var cachedMonoFontFaceCss: String? = null

/** Inlined, not a `file:///android_asset/` URL: that grants the JS-enabled WebView file origin.
 * ponytail: Regular weight only — email body isn't bold/italic-styled. Upgrade path: add more
 * weights + font-weight variants here if the renderer ever needs them. */
fun ibmPlexMonoFontFaceCss(context: Context): String {
    cachedMonoFontFaceCss?.let { return it }
    synchronized(monoFontFaceCssLock) {
        cachedMonoFontFaceCss?.let { return it }
        val bytes = context.applicationContext.assets
            .open("fonts/IBMPlexMono-Regular.ttf")
            .use { it.readBytes() }
        val css = buildMonoFontFaceCss(bytes)
        cachedMonoFontFaceCss = css
        return css
    }
}

private fun tintOverflowIcon(activity: Activity, color: Int) {
    val description = activity.getString(androidx.appcompat.R.string.abc_action_menu_overflow_description)
    val overflowButton = findViewByContentDescription(activity.window.decorView, description) as? ImageView
    overflowButton?.imageTintList = ColorStateList.valueOf(color)
}

private fun findViewByContentDescription(view: View, description: CharSequence): View? {
    if (view.contentDescription == description) return view
    if (view is ViewGroup) {
        for (index in 0 until view.childCount) {
            findViewByContentDescription(view.getChildAt(index), description)?.let { return it }
        }
    }
    return null
}

private fun applyThemeToViewTree(view: View, palette: ThemePalette) {
    val panelColor = Color.parseColor(palette.panel)
    val inkStrong = Color.parseColor(palette.inkStrong)
    val ink = Color.parseColor(palette.ink)
    val accent = Color.parseColor(palette.accent)

    when (view) {
        is EditText -> {
            view.setTextColor(inkStrong)
            view.setHintTextColor(ink)
            view.background = fieldBackground(palette)
            // A bare GradientDrawable has no padding, so text would sit flush against the border.
            val padH = (14 * density).toInt()
            val padV = (12 * density).toInt()
            view.setPadding(padH, maxOf(padV, view.paddingTop), padH, maxOf(padV, view.paddingBottom))
        }
        // Before Button, which CheckBox and RadioButton extend.
        is CheckBox, is RadioButton -> {
            applyCheckBoxTheme(view.context, view as CompoundButton)
        }
        is Button -> {
            view.setTextColor(readableOn(accent))
            view.background = buttonBackground(palette)
            applyButtonPadding(view)
        }
        // Otherwise the FAB keeps the XML theme's static colorSecondary.
        is FloatingActionButton -> {
            view.backgroundTintList = ColorStateList.valueOf(accent)
            view.imageTintList = ColorStateList.valueOf(readableOn(accent))
        }
        is TextView -> {
            // Hardcoded grayscale XML colors are template leftovers, safe to remap onto the palette.
            val current = view.currentTextColor
            if (isGrayscale(current)) {
                view.setTextColor(if (isNearWhite(current) || isNearBlack(current)) inkStrong else ink)
            }
        }
    }

    if (view is ViewGroup) {
        // The inbox list themes its own rounded CardViews in the adapter; recursing would flatten them.
        if (view is androidx.recyclerview.widget.RecyclerView) {
            return
        }
        // Always repaint, so a theme switch without a recreate refreshes already-painted containers.
        view.setBackgroundColor(panelColor)
        for (index in 0 until view.childCount) {
            applyThemeToViewTree(view.getChildAt(index), palette)
        }
    }
}

private val density: Float get() = android.content.res.Resources.getSystem().displayMetrics.density

/** Pure dp->px math, split out of [dpToPx] to be unit-testable; callers should use [dpToPx]. */
internal fun scalePxByDensity(value: Int, density: Float): Int = (value * density).toInt()

/** Converts a dp value to raw device pixels using the system-wide [density] snapshot — for raw
 *  View APIs (setPadding, LayoutParams margins) that take pixels, not dp. */
fun dpToPx(value: Int): Int = scalePxByDensity(value, density)

/** Adds [view] with vertical margins, which the plain `addView(view)` default leaves at zero. */
fun LinearLayout.addViewSpaced(view: View, topDp: Int = 0, bottomDp: Int = 0) {
    val params = LinearLayout.LayoutParams(
        LinearLayout.LayoutParams.MATCH_PARENT,
        LinearLayout.LayoutParams.WRAP_CONTENT,
    ).apply {
        topMargin = dpToPx(topDp)
        bottomMargin = dpToPx(bottomDp)
    }
    addView(view, params)
}

private fun panelBackground(context: Context, palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = context.resources.getDimension(R.dimen.card_corner_radius)
        setColor(Color.parseColor(palette.panel))
    }
}

/** Rounded `panel` background at the shared card radius (STYLE_GUIDE.md §3). */
fun applyPanelBackground(context: Context, view: View) {
    view.background = panelBackground(context, getStoredThemePalette(context))
}

private fun fieldBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 14f * density
        setColor(Color.parseColor(palette.panel))
        setStroke((2 * density).toInt(), Color.parseColor(palette.line))
    }
}

private fun buttonBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.parseColor(palette.accent))
    }
}

/** A Button's default nine-patch carries the label's padding; a GradientDrawable has none. */
private fun applyButtonPadding(button: Button) {
    val padH = (16 * density).toInt()
    val padV = (10 * density).toInt()
    button.setPadding(
        maxOf(padH, button.paddingLeft),
        maxOf(padV, button.paddingTop),
        maxOf(padH, button.paddingRight),
        maxOf(padV, button.paddingBottom),
    )
}

private fun ghostButtonBackground(palette: ThemePalette): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(Color.TRANSPARENT)
        setStroke((1 * density).toInt(), Color.parseColor(palette.line))
    }
}

private fun dangerButtonBackground(fill: Int, border: Int): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(fill)
        setStroke((1 * density).toInt(), border)
    }
}

private fun warningCalloutBackground(fill: Int, border: Int): GradientDrawable {
    return GradientDrawable().apply {
        shape = GradientDrawable.RECTANGLE
        cornerRadius = 10f * density
        setColor(fill)
        setStroke((1 * density).toInt(), border)
    }
}

private fun styledTitle(title: String, color: Int): SpannableString {
    return SpannableString(title).apply {
        setSpan(ForegroundColorSpan(color), 0, length, 0)
    }
}

/** Returns black or white — whichever reads more legibly on the given background color. */
internal fun readableOn(backgroundColor: Int): Int {
    val red = Color.red(backgroundColor)
    val green = Color.green(backgroundColor)
    val blue = Color.blue(backgroundColor)
    val darkness = 1 - (0.299 * red + 0.587 * green + 0.114 * blue) / 255
    return if (darkness >= 0.45) Color.WHITE else Color.BLACK
}

/** True for the app's dark themes; [EmailDetailActivity] uses it to override email HTML colors. */
internal fun isDarkPalette(palette: ThemePalette): Boolean = readableOn(Color.parseColor(palette.bg)) == Color.WHITE

private fun isNearWhite(color: Int): Boolean {
    return Color.red(color) > 235 && Color.green(color) > 235 && Color.blue(color) > 235
}

private fun isNearBlack(color: Int): Boolean {
    return Color.red(color) < 20 && Color.green(color) < 20 && Color.blue(color) < 20
}

/** Returns [color] with its alpha channel scaled by [fraction] (0f–1f). */
internal fun withAlpha(color: Int, fraction: Float): Int {
    val alpha = (Color.alpha(color) * fraction).toInt().coerceIn(0, 255)
    return Color.argb(alpha, Color.red(color), Color.green(color), Color.blue(color))
}

/** Linearly interpolates from [base] towards [tint] by [fraction] (0f = base, 1f = tint). */
internal fun blend(base: Int, tint: Int, fraction: Float): Int {
    return Color.rgb(
        (Color.red(base) + (Color.red(tint) - Color.red(base)) * fraction).toInt(),
        (Color.green(base) + (Color.green(tint) - Color.green(base)) * fraction).toInt(),
        (Color.blue(base) + (Color.blue(tint) - Color.blue(base)) * fraction).toInt(),
    )
}

private fun isGrayscale(color: Int): Boolean {
    val r = Color.red(color)
    val g = Color.green(color)
    val b = Color.blue(color)
    return (maxOf(r, g, b) - minOf(r, g, b)) <= 10
}

private fun actionBarSize(activity: Activity): Int {
    val typedArray = activity.theme.obtainStyledAttributes(intArrayOf(android.R.attr.actionBarSize))
    return try {
        typedArray.getDimensionPixelSize(0, 0)
    } finally {
        typedArray.recycle()
    }
}

/** [applyPanelBackground] plus a 1dp `line` stroke, for a card on a panel-coloured screen. */
fun applyOutlinedPanelBackground(context: Context, view: View) {
    val palette = getStoredThemePalette(context)
    view.background = panelBackground(context, palette).apply {
        setStroke(dpToPx(1), Color.parseColor(palette.line))
    }
}
