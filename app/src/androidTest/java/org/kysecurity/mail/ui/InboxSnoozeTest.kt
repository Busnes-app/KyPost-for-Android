package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.android.material.snackbar.Snackbar
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.MailRuntime
import java.time.Instant

/** Snooze from the selection bar: held behind Undo like any removal, then sent with its time. */
@RunWith(AndroidJUnit4::class)
class InboxSnoozeTest {

    private val source = FakeMailSource()

    @Before
    fun installRelay() {
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
    }

    @After
    fun releaseRelay() {
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    private fun email(id: String, folder: String) =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = folder)

    @Test
    fun aSnoozeHidesTheRowAndSendsItsWakeTimeWhenUndoLapses() {
        val wake = Instant.parse("2026-10-14T12:00:00Z")
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.snoozePickerForTest = { then -> then(wake) }
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("42", "INBOX")))
                activity.toggleSelectedForTest(email("42", "INBOX"))
                activity.bulkSnoozeForTest()
                assertTrue("the snooze must wait behind Undo", source.wakeAts.isEmpty())

                // Held rows are only hidden until the bar lapses; then they leave the list.
                activity.dismissUndoBarForTest(activity.undoBarForTest(), Snackbar.Callback.DISMISS_EVENT_TIMEOUT)
                assertEquals(emptyList<Email>(), activity.allEmailsForTest())
            }

            assertTrue(source.awaitCompleted(MailAction.SNOOZE))
            assertEquals(listOf(wake), source.wakeAts.toList())
        }
    }

    @Test
    fun theSnoozedFolderOffersNoSnooze() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("Snoozed", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("7", "Snoozed")))
                activity.toggleSelectedForTest(email("7", "Snoozed"))
                assertFalse(activity.hasBulkSnoozeForTest())
            }
        }
    }
}
