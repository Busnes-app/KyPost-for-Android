package org.kysecurity.mail.ui

import android.graphics.Color
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.android.material.floatingactionbutton.FloatingActionButton
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.contacts.ContactsListActivity
import org.kysecurity.mail.getStoredThemeName
import org.kysecurity.mail.readableOn
import org.kysecurity.mail.saveThemeName
import org.kysecurity.mail.themePaletteFor

@RunWith(AndroidJUnit4::class)
class ContactsFabThemeTest {

    @Test
    fun addButtonFollowsThemeAccent() {
        val context = ApplicationProvider.getApplicationContext<android.content.Context>()
        val previous = getStoredThemeName(context)
        // Not the default theme, so a match can't come from the XML colors.
        saveThemeName(context, "Forest")
        try {
            val accent = Color.parseColor(themePaletteFor("Forest", systemDark = false).accent)
            ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
                scenario.onActivity { activity ->
                    val fab = activity.findViewById<FloatingActionButton>(R.id.btnAddContact)
                    assertEquals(accent, fab.backgroundTintList?.defaultColor)
                    assertEquals(readableOn(accent), fab.imageTintList?.defaultColor)
                }
            }
        } finally {
            saveThemeName(context, previous)
        }
    }
}
