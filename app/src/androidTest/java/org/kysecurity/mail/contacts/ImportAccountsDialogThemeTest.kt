package org.kysecurity.mail.contacts

import android.content.DialogInterface
import android.graphics.Color
import android.view.View
import android.view.ViewGroup
import android.widget.CheckBox
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.contacts.device.DeviceAccount
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.THEME_PAIRS
import org.kysecurity.mail.ThemeChoice
import org.kysecurity.mail.ThemeMode
import org.kysecurity.mail.getStoredThemeChoice
import org.kysecurity.mail.saveThemeChoice
import org.kysecurity.mail.security.showSecurely
import org.kysecurity.mail.themePaletteFor
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** STYLE_GUIDE §6: dialogs stay native AlertDialogs, themed with the active palette. */
@RunWith(AndroidJUnit4::class)
class ImportAccountsDialogThemeTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private lateinit var savedTheme: ThemeChoice

    @Before
    fun setUp() {
        savedTheme = getStoredThemeChoice(context)
        saveThemeChoice(context, THEME)
    }

    @After
    fun tearDown() {
        saveThemeChoice(context, savedTheme)
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
    }

    private fun View.descendants(): Sequence<View> =
        sequenceOf(this) + ((this as? ViewGroup)?.let { g -> (0 until g.childCount).asSequence().flatMap { g.getChildAt(it).descendants() } } ?: emptySequence())

    @Test
    fun theImportDialog_takesTheActivePalette() {
        val palette = themePaletteFor(THEME, systemDark = false)
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val dialog = activity.importAccountsDialog(listOf(DeviceAccount(null, null)), mutableSetOf()) {}
                    .also { if (!it.isShowing) it.showSecurely() }
                val native = androidx.appcompat.app.AlertDialog.Builder(activity).create().also { it.show() }
                try {
                    val decor = dialog.window!!.decorView
                    // STYLE_GUIDE §3: the native background, shape and insets kept, recoloured.
                    assertEquals("native background", native.window!!.decorView.background::class, decor.background::class)
                    assertNotNull("recoloured surface", decor.background.colorFilter)
                    val box = decor.descendants().filterIsInstance<CheckBox>().single()
                    assertEquals("account text", Color.parseColor(palette.inkStrong), box.currentTextColor)
                    assertEquals(
                        "save button",
                        Color.parseColor(palette.accent),
                        dialog.getButton(DialogInterface.BUTTON_POSITIVE).currentTextColor,
                    )
                } finally {
                    dialog.dismiss()
                    native.dismiss()
                }
            }
        }
    }

    private companion object {
        // Dark, so a light default surface or text cannot pass by accident.
        val THEME = ThemeChoice(THEME_PAIRS.single { it.id == "nord-pair" }, ThemeMode.DARK)
    }
}
