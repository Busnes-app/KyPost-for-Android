package org.kysecurity.mail.ui

import android.content.DialogInterface
import android.graphics.Bitmap
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Rect
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
import org.kysecurity.mail.security.showSecurely
import org.kysecurity.mail.showThemed

/** A dialog is its own window; `showThemed` must paint it in the palette the app is using while
 *  keeping the platform's own dialog shape (STYLE_GUIDE.md §3: don't hand-tune it). */
@RunWith(AndroidJUnit4::class)
class ThemedDialogTest {

    private fun AlertDialog.Builder.sample(): AlertDialog.Builder = this
        .setTitle("Title")
        .setItems(arrayOf("Row")) { _, _ -> }
        .setNegativeButton(android.R.string.cancel, null)

    @Test
    fun titleMessageButtonsListAndSurfaceFollowThePalette() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            lateinit var plain: AlertDialog
            lateinit var dialog: AlertDialog
            scenario.onActivity { activity ->
                plain = AlertDialog.Builder(activity).sample().create().showSecurely()
                dialog = AlertDialog.Builder(activity).sample().showThemed()
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

                // Same shape as an untouched dialog: same drawable type, same insets and padding.
                val native = plain.window!!.decorView.background
                val surface = dialog.window!!.decorView.background
                assertEquals(native.javaClass, surface.javaClass)
                val nativePadding = Rect().also { native.getPadding(it) }
                val themedPadding = Rect().also { surface.getPadding(it) }
                assertEquals(nativePadding, themedPadding)

                // And it renders in the palette: the centre of the surface is panel.
                val bounds = surface.bounds
                val bitmap = Bitmap.createBitmap(bounds.width(), bounds.height(), Bitmap.Config.ARGB_8888)
                val canvas = Canvas(bitmap).apply { translate(-bounds.left.toFloat(), -bounds.top.toFloat()) }
                surface.draw(canvas)
                assertEquals(
                    Integer.toHexString(Color.parseColor(palette.panel)),
                    Integer.toHexString(bitmap.getPixel(bitmap.width / 2, bitmap.height / 2)),
                )
                plain.dismiss()
                dialog.dismiss()
            }
        }
    }
}
