package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R

/** #131: a refresh that lands mail above the visible rows must not leave it unseen off-screen. */
@RunWith(AndroidJUnit4::class)
class InboxNewMailTest {

    private fun rows(ids: List<String>) = ids.map {
        Email(id = it, subject = "Subject $it", sender = "sender@example.com", preview = "", folder = FOLDER)
    }

    private val older = rows((1..40).map { "old$it" })
    private val newer = rows(listOf("new1", "new2"))

    private fun idle() = InstrumentationRegistry.getInstrumentation().waitForIdleSync()

    /** A folder no launch refresh targets, so only this test's refreshes paint it. */
    private fun ActivityScenario<InboxActivity>.paint(emails: List<Email>) = onActivity {
        it.applyRefreshedEmails(FOLDER, emails, isFinal = true, errorMessage = null)
    }

    @Test
    fun atTheTopNewMailIsScrolledIntoView() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { it.setFolderForTest(FOLDER, KeywordTabs.ALL) }
            scenario.paint(older)
            idle()

            scenario.paint(newer + older)
            idle()

            scenario.onActivity {
                assertEquals(0, it.firstVisiblePositionForTest())
                assertNull(it.newMailPillTextForTest())
            }
        }
    }

    @Test
    fun scrolledAwayNewMailShowsACountingPillThatScrollsUp() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity {
                it.setFolderForTest(FOLDER, KeywordTabs.ALL)
                it.setPendingScrollPositionForTest(30)
            }
            scenario.paint(older)
            idle()

            scenario.paint(newer + older)
            idle()
            scenario.onActivity { assertEquals("2 new messages", it.newMailPillTextForTest()) }

            scenario.paint(rows(listOf("new0")) + newer + older)
            idle()
            scenario.onActivity { assertEquals("3 new messages", it.newMailPillTextForTest()) }

            onView(withId(R.id.newMailPill)).perform(click())
            idle()
            scenario.onActivity { assertNull(it.newMailPillTextForTest()) }
        }
    }

    @Test
    fun aFirstPaintOfAFolderAnnouncesNothing() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            // Another folder's rows, scrolled away from the top, still on screen after a switch.
            val elsewhere = rows((1..40).map { "elsewhere$it" })
            scenario.onActivity {
                it.setFolderForTest(FOLDER, KeywordTabs.ALL)
                it.setEmailsForTest(elsewhere)
                it.setPendingScrollPositionForTest(30)
                it.setEmailsForTest(elsewhere)
            }
            idle()

            scenario.paint(newer + older)
            idle()

            scenario.onActivity { assertNull(it.newMailPillTextForTest()) }
        }
    }

    private companion object {
        const val FOLDER = "Archive/NewMailTest"
    }
}
