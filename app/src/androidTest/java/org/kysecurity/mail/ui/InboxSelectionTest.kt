package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.ViewMatchers.withContentDescription
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.mail.MailRuntime

@RunWith(AndroidJUnit4::class)
class InboxSelectionTest {

    @After
    fun releaseRuntime() {
        MailRuntime.invalidate()
    }

    private fun email(id: String) =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = "INBOX")

    private fun withInbox(block: (InboxActivity) -> Unit) {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2"), email("3")))
                block(activity)
            }
        }
    }

    @Test
    fun selectingTheLastRowAwayEndsSelectionMode() = withInbox { activity ->
        activity.toggleSelectedForTest(email("1"))
        activity.toggleSelectedForTest(email("3"))
        assertTrue(activity.inSelectionModeForTest())
        assertEquals(setOf("1", "3"), activity.selectedIdsForTest())

        activity.toggleSelectedForTest(email("1"))
        activity.toggleSelectedForTest(email("3"))
        assertFalse(activity.inSelectionModeForTest())
        assertEquals(emptySet<String>(), activity.selectedIdsForTest())
    }

    @Test
    fun aFolderSwitchEndsSelectionMode() = withInbox { activity ->
        activity.toggleSelectedForTest(email("2"))
        activity.switchFolderForTest("Archive")
        assertFalse(activity.inSelectionModeForTest())
        assertEquals(emptySet<String>(), activity.selectedIdsForTest())
    }

    /** "2 selected" means two: a row selected under another keyword tab is still selected. */
    @Test
    fun aBulkActionCoversRowsSelectedInOtherTabs() {
        val work = Email(id = "w", subject = "w", sender = "a@example.com", preview = "", folder = "INBOX", keywords = setOf("Work"))
        val home = Email(id = "h", subject = "h", sender = "a@example.com", preview = "", folder = "INBOX", keywords = setOf("Home"))
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", "Work")
                activity.setEmailsForTest(listOf(work, home))
                activity.toggleSelectedForTest(work)
                activity.setFolderForTest("INBOX", "Home")
                activity.setEmailsForTest(listOf(work, home))
                activity.toggleSelectedForTest(home)
                assertEquals(setOf("w", "h"), activity.selectedIdsForTest())
            }
            onView(withContentDescription("Archive")).perform(click())
            // Leaving the screen sends anything still held for Undo.
            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.onActivity { activity ->
                assertEquals(emptyList<String>(), activity.allEmailsForTest().map { it.id })
            }
        }
    }
}
