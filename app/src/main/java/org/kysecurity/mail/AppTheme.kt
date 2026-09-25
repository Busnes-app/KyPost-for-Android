package org.kysecurity.mail

import android.app.Activity
import android.content.Context
import android.content.res.ColorStateList
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
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.core.view.WindowInsetsControllerCompat

const val THEME_STORAGE_KEY = "kypost-theme"

/** Fallback when nothing is saved, and when a saved name is no longer offered. */
const val DEFAULT_THEME = "Busnes Light"

val THEME_OPTIONS = listOf(
    "Busnes Light",
    "Busnes Dark",
    "Dark Matter",
    "Light Matter",
    "Tropics",
    "Tropic Night",
    "Ocean",
    "Coffee",
    "White Cliffs",
    "Cyber Punk",
    "Neon Purple",
    "Space",
    "Sky",
    "Forest",
    "Sun",
    "Patina Ky",
    "Polished Ky",
)

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
)

// Semantic colors are theme-invariant on web (fixed literals in styles.css, not per-theme
// palette fields) — mirrored here as constants rather than ThemePalette fields.
const val COLOR_DANGER = "#ff5f5f"
const val COLOR_DANGER_ACTION_BORDER = "#66FFB4AB" // rgba(255,180,171,.4)
const val COLOR_DANGER_ACTION_FILL = "#1FFFB4AB" // rgba(255,180,171,.12)
const val COLOR_DANGER_ACTION_TEXT = "#ffd8d3"
const val COLOR_WARNING = "#ffd64d"
const val COLOR_WARNING_ACTION_BORDER = "#66FFD64D" // rgba(255,214,77,.4)
const val COLOR_WARNING_ACTION_FILL = "#1FFFD64D" // rgba(255,214,77,.12)
const val COLOR_WARNING_ACTION_TEXT = "#fff0b8"
const val COLOR_SUCCESS_BORDER = "#7bbf7b"
const val COLOR_SUCCESS_TEXT = "#a5dca5"

internal val themePalettes: Map<String, ThemePalette> = mapOf(
    // Busnes cream/charcoal, one orange accent (busnes-color-theme-handoff.md). `line` is the
    // handoff's control border composited onto `panel` — blend() drops alpha, so a translucent
    // line would paint applyEmptyStateBackground's dashed border near-black on cream.
    // Avatar stops run accent -> decorative orange; buttonText falls out of readableOn(accent).
    "Busnes Light" to ThemePalette("#f8f6f0", "#ffffff", "#566461", "#182326", "#bf3f18", "#cccfcf", "#bf3f18", "#e65124", "#bf3f18"),
    "Busnes Dark" to ThemePalette("#182326", "#1f2b2e", "#b3bcb8", "#f2efe8", "#f5865f", "#525a5b", "#f5865f", "#f26a3d", "#f5865f"),
    "Dark Matter" to ThemePalette("#1a1a1e", "#252530", "#d4c5e2", "#e8ddf5", "#c29a72", "#404050", "#c29a72", "#9a7450", "#8f6b4a"),
    "Light Matter" to ThemePalette("#f5efe5", "#fff8ee", "#4c3d32", "#2d1f15", "#c29a72", "#c5b29d", "#c29a72", "#9a7450", "#8f6b4a"),
    "Tropics" to ThemePalette("#f4f1eb", "#fffaf0", "#43362d", "#241a14", "#9bc400", "#c4b7a3", "#9bc400", "#7ea100", "#78a100"),
    "Tropic Night" to ThemePalette("#15131a", "#221f2b", "#cdbde0", "#e8ddf5", "#9bc400", "#3c3650", "#9bc400", "#7ea100", "#78a100"),
    "Ocean" to ThemePalette("#0f1b24", "#152a36", "#b8d8e8", "#e0f2fb", "#5ea9be", "#2f5567", "#74bacd", "#4f91a6", "#4f91a6"),
    "Coffee" to ThemePalette("#1d1714", "#2a211d", "#d6c0b3", "#f0ded2", "#b47f5c", "#4a3830", "#b47f5c", "#8f5f42", "#8f5f42"),
    "White Cliffs" to ThemePalette("#f7f9fb", "#ffffff", "#2e4c63", "#163246", "#5ea8d8", "#8fc3df", "#4f9bc8", "#58b65a", "#2f7fb0"),
    "Cyber Punk" to ThemePalette("#120918", "#1e1028", "#f5d0ff", "#ffe9ff", "#00f5d4", "#5c2d84", "#00f5d4", "#00c9ad", "#00c9ad"),
    "Neon Purple" to ThemePalette("#130b1d", "#231233", "#e4ccff", "#f2e6ff", "#c86cff", "#63358a", "#c86cff", "#9d45d3", "#9d45d3"),
    "Space" to ThemePalette("#0b0f1a", "#151c2d", "#c8d5f0", "#e7efff", "#86a8ff", "#34496f", "#86a8ff", "#6788dd", "#6788dd"),
    "Sky" to ThemePalette("#dff1ff", "#f4fbff", "#2f4f64", "#183142", "#6db3d6", "#93bdd2", "#6db3d6", "#4f93b8", "#4f93b8"),
    "Forest" to ThemePalette("#142018", "#1f2f24", "#c7dbc7", "#e3f0df", "#8faa74", "#4f694f", "#8faa74", "#6f8d5a", "#6f8d5a"),
    "Sun" to ThemePalette("#fff3dc", "#fff9ec", "#5a4024", "#392611", "#e0ab4f", "#d4b27a", "#e0ab4f", "#bb8631", "#bb8631"),
    "Patina Ky" to ThemePalette("#0d0f14", "#161a22", "#64748b", "#e2e8f0", "#4deeea", "#1e293b", "#4deeea", "#10b981", "#0e9668"),
    "Polished Ky" to ThemePalette("#eef2f6", "#ffffff", "#475569", "#0f172a", "#0891b2", "#cbd5e1", "#0891b2", "#10b981", "#059669"),
)

fun getStoredThemeName(context: Context): String {
    val prefs = context.getSharedPreferences("org.kysecurity.mail.settings", Context.MODE_PRIVATE)
    val saved = prefs.getString(THEME_STORAGE_KEY, DEFAULT_THEME) ?: DEFAULT_THEME
    return if (THEME_OPTIONS.contains(saved)) saved else DEFAULT_THEME
}

fun saveThemeName(context: Context, themeName: String) {
    val prefs = context.getSharedPreferences("org.kysecurity.mail.settings", Context.MODE_PRIVATE)
    prefs.edit().putString(THEME_STORAGE_KEY, themeName).apply()
}

fun getStoredThemePalette(context: Context): ThemePalette {
    return themePaletteFor(getStoredThemeName(context))
}

fun themePaletteFor(themeName: String): ThemePalette {
    return themePalettes[themeName] ?: themePalettes.getValue(DEFAULT_THEME)
}

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

fun applyCheckBoxTheme(context: Context, checkBox: CheckBox) {
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

/** Pads the view's bottom by the system navigation-bar inset so edge-to-edge content (e.g. the
 *  bottom navigation bar) clears the gesture/nav area. */
fun applyBottomInset(view: View) {
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bottomInset = insets.getInsets(WindowInsetsCompat.Type.systemBars()).bottom
        v.setPadding(v.paddingLeft, v.paddingTop, v.paddingRight, basePaddingBottom + bottomInset)
        insets
    }
    ViewCompat.requestApplyInsets(view)
}

/** Rail equivalent of [applyBottomInset]: a full-height rail also needs top and start insets. */
fun applyRailInsets(activity: Activity, view: View) {
    val basePaddingStart = view.paddingStart
    val basePaddingTop = view.paddingTop
    val basePaddingBottom = view.paddingBottom
    ViewCompat.setOnApplyWindowInsetsListener(view) { v, insets ->
        val bars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
        val startInset = if (v.layoutDirection == View.LAYOUT_DIRECTION_RTL) bars.right else bars.left
        v.setPaddingRelative(
            basePaddingStart + startInset,
            basePaddingTop + bars.top + actionBarSize(activity),
            v.paddingEnd,
            basePaddingBottom + bars.bottom,
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

/** 1dp stroke + 12% fill of the fixed danger red, mirrors web's `.users-action-danger` /
 *  `.contacts-action-danger`. Use for destructive actions (delete), never theme-accent. */
fun applyDangerButtonTheme(context: Context, button: Button) {
    val (fill, border, text) = accentAffordanceColors(
        context,
        Color.parseColor(COLOR_DANGER),
        Color.parseColor(COLOR_DANGER_ACTION_TEXT),
    )
    button.backgroundTintList = null
    button.background = dangerButtonBackground(fill, border)
    button.setTextColor(text)
    applyButtonPadding(button)
}

/** Warning-tinted informational callout: the danger-button stroke+fill shape, on a TextView. */
fun applyWarningCalloutTheme(context: Context, textView: TextView) {
    val (fill, border, text) = accentAffordanceColors(
        context,
        Color.parseColor(COLOR_WARNING),
        Color.parseColor(COLOR_WARNING_ACTION_TEXT),
    )
    textView.background = warningCalloutBackground(fill, border)
    textView.setTextColor(text)
}

/** Success chip state. Pass [animate] only from the tap; per-bind recycled rows stay instant. */
fun applySuccessChipTheme(
    context: Context,
    chip: com.google.android.material.chip.Chip,
    animate: Boolean = false,
) {
    val border = Color.parseColor(COLOR_SUCCESS_BORDER)
    val toBg = withAlpha(border, 0.12f)
    val toStroke = border
    val toText = Color.parseColor(COLOR_SUCCESS_TEXT)
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

/** Status badge + dot: [active] is fixed success green, inactive is theme line/panel/ink. */
fun applyStatusBadgeTheme(context: Context, chip: com.google.android.material.chip.Chip, active: Boolean) {
    val palette = getStoredThemePalette(context)
    val border: Int
    val text: Int
    val fill: Int
    if (active) {
        border = Color.parseColor(COLOR_SUCCESS_BORDER)
        text = Color.parseColor(COLOR_SUCCESS_TEXT)
        fill = withAlpha(border, 0.12f)
    } else {
        border = Color.parseColor(palette.line)
        text = Color.parseColor(palette.ink)
        fill = Color.parseColor(palette.panel)
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
        is Button -> {
            view.setTextColor(readableOn(accent))
            view.background = buttonBackground(palette)
            applyButtonPadding(view)
        }
        is CheckBox -> {
            applyCheckBoxTheme(view.context, view)
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

/** §1's pale tints measure ~1.1:1 on light panels, so the hue is driven toward black there. */
private fun accentAffordanceColors(context: Context, hue: Int, darkThemeText: Int): Triple<Int, Int, Int> {
    return if (isDarkPalette(getStoredThemePalette(context))) {
        Triple(withAlpha(hue, 0.12f), withAlpha(hue, 0.40f), darkThemeText)
    } else {
        // A heavier fill and stroke because a 12%/40% tint of a bright hue is nearly invisible on a
        // near-white panel, and text driven most of the way to black so it clears 4.5:1 there.
        Triple(withAlpha(hue, 0.18f), withAlpha(hue, 0.65f), blend(hue, Color.BLACK, 0.55f))
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
    val darkness = 1 - (0.299 * Color.red(backgroundColor) + 0.587 * Color.green(backgroundColor) + 0.114 * Color.blue(backgroundColor)) / 255
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
