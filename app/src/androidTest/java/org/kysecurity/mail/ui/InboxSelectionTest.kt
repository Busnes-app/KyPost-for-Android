package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs

@RunWith(AndroidJUnit4::class)
class InboxSelectionTest {

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
}
