package org.kysecurity.mail

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.graphics.drawable.LayerDrawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.RadioGroup
import android.widget.TextView
import org.kysecurity.mail.security.LockedActivity

/** The pair picker plus a System / Light / Dark choice (ky-ui's Appearance page, natively). */
class ThemesActivity : LockedActivity() {

    private val modeButtons = mapOf(
        ThemeMode.SYSTEM to R.id.themeModeSystem,
        ThemeMode.LIGHT to R.id.themeModeLight,
        ThemeMode.DARK to R.id.themeModeDark,
    )

    private lateinit var listView: ListView

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_themes)
        setTitle(R.string.themes_title)

        val root = findViewById<View>(R.id.themesRoot)
        applyTopInsetWithHeader(this, root)

        listView = findViewById(R.id.themeList)
        listView.adapter = object : ArrayAdapter<String>(
            this,
            android.R.layout.simple_list_item_single_choice,
            THEME_PAIRS.map { it.name },
        ) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val row = super.getView(position, convertView, parent) as TextView
                val activePalette = getStoredThemePalette(this@ThemesActivity)
                row.background = GradientDrawable().apply {
                    shape = GradientDrawable.RECTANGLE
                    cornerRadius = 16 * resources.displayMetrics.density
                    setColor(Color.parseColor(activePalette.panel))
                    setStroke(dpToPx(1), Color.parseColor(activePalette.line))
                }
                row.setPadding(dpToPx(16), dpToPx(14), dpToPx(16), dpToPx(14))
                row.setTextColor(Color.parseColor(activePalette.inkStrong))
                row.compoundDrawablePadding = dpToPx(16)
                row.setCompoundDrawablesRelativeWithIntrinsicBounds(pairPreview(THEME_PAIRS[position]), null, null, null)
                row.contentDescription = getString(R.string.themes_pair_description, THEME_PAIRS[position].name)
                return row
            }
        }
        listView.choiceMode = ListView.CHOICE_MODE_SINGLE

        val stored = getStoredThemeChoice(this)
        listView.setItemChecked(THEME_PAIRS.indexOf(stored.pair).coerceAtLeast(0), true)
        val modeGroup = findViewById<RadioGroup>(R.id.themeModeGroup)
        modeGroup.check(modeButtons.getValue(stored.mode))

        listView.setOnItemClickListener { _, _, position, _ ->
            choose(getStoredThemeChoice(this).copy(pair = THEME_PAIRS[position]))
        }
        modeGroup.setOnCheckedChangeListener { _, checkedId ->
            val mode = modeButtons.entries.first { it.value == checkedId }.key
            choose(getStoredThemeChoice(this).copy(mode = mode))
        }
        paint()
    }

    private fun choose(choice: ThemeChoice) {
        if (choice == getStoredThemeChoice(this)) return
        saveThemeChoice(this, choice)
        paint()
    }

    private fun paint() {
        applyThemeToActivity(this)
        applySectionEyebrowLabel(this, findViewById(R.id.themeModeLabel))
        applySectionEyebrowLabel(this, findViewById(R.id.themePairLabel))
        (listView.adapter as ArrayAdapter<*>).notifyDataSetChanged()
    }

    /** Both halves side by side: each a circle of its bg ringed in its accent. */
    private fun pairPreview(pair: ThemePair): LayerDrawable {
        val size = dpToPx(22)
        fun half(palette: ThemePalette) = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setSize(size, size)
            setColor(Color.parseColor(palette.bg))
            setStroke(dpToPx(4), Color.parseColor(palette.accent))
        }
        return LayerDrawable(arrayOf(half(pair.light), half(pair.dark))).apply {
            setLayerInset(0, 0, 0, size + dpToPx(4), 0)
            setLayerInset(1, size + dpToPx(4), 0, 0, 0)
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        paint()
    }
}
