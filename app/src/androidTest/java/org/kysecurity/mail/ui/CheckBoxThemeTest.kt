package org.kysecurity.mail.ui

import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.ViewGroup
import android.widget.Button
import android.widget.CheckBox
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.SettingsActivity
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.getStoredThemePalette

/** CheckBox is a Button subclass; the tree walk must give it the checkbox theme, not a button's. */
@RunWith(AndroidJUnit4::class)
class CheckBoxThemeTest {

    @Test
    fun aCheckBoxGetsTheCheckBoxThemeAndAButtonKeepsTheButtonTheme() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val checkBox = CheckBox(activity)
                val button = Button(activity)
                activity.findViewById<ViewGroup>(android.R.id.content).run {
                    addView(checkBox)
                    addView(button)
                }
                applyThemeToActivity(activity)

                val palette = getStoredThemePalette(activity)
                assertEquals(Color.parseColor(palette.accent), checkBox.buttonTintList?.defaultColor)
                assertEquals(Color.parseColor(palette.inkStrong), checkBox.currentTextColor)
                assertFalse("a checkbox got the button background", checkBox.background is GradientDrawable)
                assertTrue(button.background is GradientDrawable)
            }
        }
    }
}
