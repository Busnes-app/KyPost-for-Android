package org.kysecurity.mail.contacts

import android.content.DialogInterface
import android.graphics.Color
import android.graphics.drawable.GradientDrawable
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.contacts.device.DeviceAccount
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.getStoredThemeName
import org.kysecurity.mail.saveThemeName
import org.kysecurity.mail.security.showSecurely
import org.kysecurity.mail.themePaletteFor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** STYLE_GUIDE §6: dialogs stay native AlertDialogs, themed with the active palette. */
@RunWith(AndroidJUnit4::class)
class ImportAccountsDialogThemeTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private lateinit var savedTheme: String

    @Before
    fun setUp() {
        savedTheme = getStoredThemeName(context)
        saveThemeName(context, THEME)
    }

    @After
    fun tearDown() {
        saveThemeName(context, savedTheme)
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
    }

    private fun View.descendants(): Sequence<View> =
        sequenceOf(this) + ((this as? ViewGroup)?.let { g -> (0 until g.childCount).asSequence().flatMap { g.getChildAt(it).descendants() } } ?: emptySequence())

    @Test
    fun theImportDialog_takesTheActivePalette() {
        val palette = themePaletteFor(THEME)
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val dialog = activity.importAccountsDialog(listOf(DeviceAccount(null, null)), mutableSetOf()) {}.showSecurely()
                try {
                    val decor = dialog.window!!.decorView
                    assertEquals(
                        "surface",
                        Color.parseColor(palette.panel),
                        (decor.background as? GradientDrawable)?.color?.defaultColor,
                    )
                    val box = decor.descendants().filterIsInstance<CheckBox>().single()
                    assertEquals("account text", Color.parseColor(palette.ink), box.currentTextColor)
                    assertEquals(
                        "save button",
                        Color.parseColor(palette.accent),
                        dialog.getButton(DialogInterface.BUTTON_POSITIVE).currentTextColor,
                    )
                } finally {
                    dialog.dismiss()
                }
            }
        }
    }

    private companion object {
        // Dark, so a light default surface or text cannot pass by accident.
        const val THEME = "Space"
    }
}
