package org.kysecurity.mail

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.ArrayAdapter
import android.widget.ListView
import android.widget.TextView
import org.kysecurity.mail.security.LockedActivity

class ThemesActivity : LockedActivity() {

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_themes)
        setTitle(R.string.themes_title)
        applyThemeToActivity(this)

        val root = findViewById<View>(R.id.themesRoot)
        applyTopInsetWithHeader(this, root)

        val listView = findViewById<ListView>(R.id.themeList)
        val adapter = object : ArrayAdapter<String>(
            this,
            android.R.layout.simple_list_item_single_choice,
            THEME_OPTIONS,
        ) {
            override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
                val row = super.getView(position, convertView, parent) as TextView
                val activePalette = getStoredThemePalette(this@ThemesActivity)
                val cornerRadius = 16 * resources.displayMetrics.density
                row.background = GradientDrawable().apply {
                    shape = GradientDrawable.RECTANGLE
                    this.cornerRadius = cornerRadius
                    setColor(Color.parseColor(activePalette.panel))
                    setStroke(
                        (1 * resources.displayMetrics.density).toInt(),
                        Color.parseColor(activePalette.line),
                    )
                }
                val padH = (16 * resources.displayMetrics.density).toInt()
                val padV = (14 * resources.displayMetrics.density).toInt()
                row.setPadding(padH, padV, padH, padV)
                row.setTextColor(Color.parseColor(activePalette.inkStrong))

                val rowPalette = themePaletteFor(THEME_OPTIONS[position], isSystemDark(this@ThemesActivity))
                val swatchSize = (22 * resources.displayMetrics.density).toInt()
                val swatch = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setSize(swatchSize, swatchSize)
                    setColor(Color.parseColor(rowPalette.accent))
                    setStroke((1 * resources.displayMetrics.density).toInt(), Color.parseColor(rowPalette.line))
                }
                row.compoundDrawablePadding = (16 * resources.displayMetrics.density).toInt()
                row.setCompoundDrawablesWithIntrinsicBounds(swatch, null, null, null)
                return row
            }
        }
        listView.adapter = adapter
        listView.choiceMode = ListView.CHOICE_MODE_SINGLE

        val selectedTheme = getStoredThemeName(this)
        val selectedIndex = THEME_OPTIONS.indexOf(selectedTheme).coerceAtLeast(0)
        listView.setItemChecked(selectedIndex, true)

        listView.setOnItemClickListener { _, _, position, _ ->
            val chosen = THEME_OPTIONS[position]
            saveThemeName(this, chosen)
            applyThemeToActivity(this)
            (listView.adapter as ArrayAdapter<*>).notifyDataSetChanged()
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
    }
}
