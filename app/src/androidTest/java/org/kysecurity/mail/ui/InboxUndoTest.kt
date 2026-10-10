package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A swipe hides the row at once but asks the server nothing until the undo window closes. */
@RunWith(AndroidJUnit4::class)
class InboxUndoTest {

    private fun email(id: String) =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = "INBOX")

    @Test
    fun undoBringsTheRowBackAndNothingIsSent() {
        val ran = CountDownLatch(1)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.rowActionObserverForTest = { _, _ -> ran.countDown() }
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2")))
                activity.submitDeleteForTest(email("1"))
                assertEquals(listOf("2"), activity.shownEmailsForTest().map { it.id })
            }

            onView(withText("Undo")).perform(click())

            scenario.onActivity { activity ->
                assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
            }
            assertFalse("an undone delete reached the server", ran.await(7, TimeUnit.SECONDS))
            scenario.onActivity { it.rowActionObserverForTest = null }
        }
    }

    @Test
    fun leavingTheScreenSendsWhatIsStillHeld() {
        val ran = CountDownLatch(1)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.rowActionObserverForTest = { _, _ -> ran.countDown() }
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1")))
                activity.submitDeleteForTest(email("1"))
            }

            scenario.moveToState(Lifecycle.State.CREATED)

            assertTrue("the held delete never ran", ran.await(3, TimeUnit.SECONDS))
            scenario.onActivity { it.rowActionObserverForTest = null }
        }
    }
}
