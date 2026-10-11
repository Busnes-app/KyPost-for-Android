package org.kysecurity.mail.ui

import android.content.DialogInterface
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.widget.TextView
import androidx.appcompat.app.AlertDialog
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.SettingsActivity
import org.kysecurity.mail.getStoredThemePalette
import org.kysecurity.mail.showThemed

/** A dialog is its own window; `showThemed` must paint it in the palette the app is using. */
@RunWith(AndroidJUnit4::class)
class ThemedDialogTest {

    @Test
    fun titleMessageButtonsListAndSurfaceFollowThePalette() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            lateinit var dialog: AlertDialog
            scenario.onActivity { activity ->
                dialog = AlertDialog.Builder(activity)
                    .setTitle("Title")
                    .setItems(arrayOf("Row")) { _, _ -> }
                    .setNegativeButton(android.R.string.cancel, null)
                    .showThemed()
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                val palette = getStoredThemePalette(activity)
                val title = dialog.findViewById<TextView>(androidx.appcompat.R.id.alertTitle)!!
                assertEquals(Color.parseColor(palette.inkStrong), title.currentTextColor)
                assertEquals(
                    Color.parseColor(palette.accent),
                    dialog.getButton(DialogInterface.BUTTON_NEGATIVE).currentTextColor,
                )
                val row = dialog.listView.getChildAt(0) as TextView
                assertEquals(Color.parseColor(palette.inkStrong), row.currentTextColor)
                val surface = dialog.window!!.decorView.background as GradientDrawable
                assertEquals(Color.parseColor(palette.panel), surface.color!!.defaultColor)
                dialog.dismiss()
            }
        }
    }
}
