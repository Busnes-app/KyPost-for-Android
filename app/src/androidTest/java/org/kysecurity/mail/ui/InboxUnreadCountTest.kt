package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordSettings
import org.kysecurity.mail.R

/** The chip text carries the count; the keyword, and the selection, live in the tag. */
@RunWith(AndroidJUnit4::class)
class InboxUnreadCountTest {

    private val keywordSettings =
        KeywordSettings(InstrumentationRegistry.getInstrumentation().targetContext)

    @Before
    fun showOneKeywordOnly() {
        keywordSettings.rememberKeywords(setOf(TAB_KEYWORD))
        keywordSettings.setKeywordVisible(TAB_KEYWORD, true)
        keywordSettings.setAllTabVisible(false)
    }

    @After
    fun restoreDefaults() {
        keywordSettings.setAllTabVisible(true)
        keywordSettings.setKeywordVisible(TAB_KEYWORD, false)
    }

    private fun email(id: String, status: String) =
        Email(id = id, subject = "s", sender = "a", preview = "", keywords = setOf(TAB_KEYWORD), folder = FOLDER, status = status)

    @Test
    fun theCountChangesTheTextButNotTheChipOrItsSelection() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                // A folder no real refresh is fetching, so nothing repaints the strip under the test.
                activity.setFolderForTest(FOLDER, TAB_KEYWORD)
                val chips = activity.findViewById<ChipGroup>(R.id.keywordChipGroup)

                activity.applyRefreshedEmails(FOLDER, listOf(email("1", "unread"), email("2", "read")), isFinal = false, errorMessage = null)
                val chip = chips.findViewWithTag<Chip>(TAB_KEYWORD)
                assertEquals(TAB_KEYWORD, chip.tag)
                assertEquals("$TAB_KEYWORD · 1", chip.text.toString().replace(Regex("[\u2066-\u2069\u200E\u200F]"), ""))
                assertEquals("$TAB_KEYWORD, 1 unread", chip.contentDescription)

                activity.applyRefreshedEmails(FOLDER, listOf(email("1", "read"), email("2", "read")), isFinal = false, errorMessage = null)
                assertSame("a count change must not rebuild the chip", chip, chips.findViewWithTag<Chip>(TAB_KEYWORD))
                assertEquals(TAB_KEYWORD, chip.text.toString())
                assertNull(chip.contentDescription)
                assertEquals(chip.id, chips.checkedChipId)
                assertEquals(TAB_KEYWORD, activity.selectedTabForTest())
            }
        }
    }

    private companion object {
        const val TAB_KEYWORD = "Finance"
        const val FOLDER = "UnreadCountTestFolder"
    }
}
