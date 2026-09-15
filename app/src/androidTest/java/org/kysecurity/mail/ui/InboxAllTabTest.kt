package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordSettings
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R

/** Issue #38: the All tab can be hidden in Keyword Settings like any keyword tab. */
@RunWith(AndroidJUnit4::class)
class InboxAllTabTest {

    private val keywordSettings =
        KeywordSettings(InstrumentationRegistry.getInstrumentation().targetContext)

    @Before
    fun hideAllAndShowOneKeyword() {
        keywordSettings.rememberKeywords(setOf(TAB_KEYWORD))
        keywordSettings.setKeywordVisible(TAB_KEYWORD, true)
        keywordSettings.setAllTabVisible(false)
    }

    @After
    fun restoreDefaults() {
        keywordSettings.setAllTabVisible(true)
        keywordSettings.setKeywordVisible(TAB_KEYWORD, false)
    }

    @Test
    fun aHiddenAllTabIsNotChippedAndTheFirstKeywordIsSelected() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val chips = activity.findViewById<ChipGroup>(R.id.keywordChipGroup)
                val labels = (0 until chips.childCount).map { (chips.getChildAt(it) as Chip).text.toString() }

                assertEquals(listOf(TAB_KEYWORD), labels)
                assertEquals(TAB_KEYWORD, activity.selectedTabForTest())
            }
        }
    }

    /** A relay label spelt "All" must neither become a chip nor alias the app-owned tab. */
    @Test
    fun aRelayLabelSpeltAllDoesNotBecomeASecondAllTab() {
        keywordSettings.rememberKeywords(setOf(KeywordTabs.ALL, "all"))

        assertFalse(keywordSettings.getOrderedKeywords().any { it.equals(KeywordTabs.ALL, ignoreCase = true) })
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val chips = activity.findViewById<ChipGroup>(R.id.keywordChipGroup)
                val labels = (0 until chips.childCount).map { (chips.getChildAt(it) as Chip).text.toString() }

                assertEquals(listOf(TAB_KEYWORD), labels)
            }
        }
    }

    private companion object {
        const val TAB_KEYWORD = "Finance"
    }
}
