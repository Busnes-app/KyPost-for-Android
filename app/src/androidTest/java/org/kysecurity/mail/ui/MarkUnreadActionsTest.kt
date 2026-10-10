package org.kysecurity.mail.ui

import android.app.Activity
import android.content.Intent
import android.widget.ImageButton
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onIdle
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.RootMatchers.isPlatformPopup
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.MailActionOutcome
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import java.util.concurrent.CountDownLatch

/** Mark read / Mark unread against a relay the test controls: the detail button's result and
 *  recovery, the row menu, and the order a pending read and an unread reach the server in. */
@RunWith(AndroidJUnit4::class)
class MarkUnreadActionsTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

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

    private fun detailIntent(id: String = ID, folder: String = INBOX) =
        Intent(context, EmailDetailActivity::class.java)
            .putExtra("email_id", id)
            .putExtra("email_folder", folder)

    private fun row(folder: String, status: String) =
        Email(id = ID, subject = "Subject", sender = "sender@example.com", preview = "", folder = folder, status = status)

    private fun ActivityScenario<EmailDetailActivity>.tapMarkUnread() =
        onActivity { it.findViewById<ImageButton>(R.id.actionMarkUnread).performClick() }

    private fun ActivityScenario<InboxActivity>.chooseFromRowMenu(label: String) {
        onIdle()
        onActivity { activity ->
            val list = activity.findViewById<RecyclerView>(R.id.recyclerViewInbox)
            list.findViewHolderForAdapterPosition(0)!!.itemView.performLongClick()
        }
        onView(withText(label)).inRoot(isPlatformPopup()).perform(click())
    }

    @Test
    fun detailMarkUnreadFinishesWithTheConfirmedRowAfterTheRead() {
        ActivityScenario.launchActivityForResult<EmailDetailActivity>(detailIntent()).use { scenario ->
            assertTrue(source.awaitCompleted(MailAction.READ))
            scenario.tapMarkUnread()

            assertTrue(source.awaitCompleted(MailAction.UNREAD))
            onIdle()
            assertEquals(Activity.RESULT_OK, scenario.result.resultCode)
            assertEquals(ID, scenario.result.resultData.getStringExtra(EmailDetailActivity.EXTRA_MARKED_UNREAD_ID))
            assertEquals(INBOX, scenario.result.resultData.getStringExtra(EmailDetailActivity.EXTRA_MARKED_UNREAD_FOLDER))
            assertEquals(listOf(MailAction.READ, MailAction.UNREAD), source.completed.toList())
        }
    }

    @Test
    fun aRejectedMarkUnreadKeepsTheScreenAndGivesTheButtonBack() {
        source.actionOutcome = { action ->
            if (action == MailAction.UNREAD) {
                MailOutcome.Success(MailActionOutcome(processed = 0, failed = listOf(ID to "mailbox is read-only")))
            } else {
                MailOutcome.Success(MailActionOutcome(processed = 1, failed = emptyList()))
            }
        }
        ActivityScenario.launch<EmailDetailActivity>(detailIntent()).use { scenario ->
            scenario.tapMarkUnread()
            assertTrue(source.awaitCompleted(MailAction.UNREAD))
            onIdle()

            scenario.onActivity { activity ->
                assertFalse("a rejected unread must not close the message", activity.isFinishing)
                assertTrue(activity.findViewById<ImageButton>(R.id.actionMarkUnread).isEnabled)
            }
        }
    }

    /** Reopening while the first open's read is still in flight must not let unread overtake it. */
    @Test
    fun unreadAfterAReopenLandsAfterTheFirstOpensRead() {
        val firstRead = CountDownLatch(1)
        source.readGates.add(firstRead)
        ActivityScenario.launch<EmailDetailActivity>(detailIntent()).use { }
        ActivityScenario.launch<EmailDetailActivity>(detailIntent()).use { scenario ->
            scenario.tapMarkUnread()
            // Give an unordered unread every chance to overtake the held read before releasing it.
            source.awaitCompleted(MailAction.UNREAD, seconds = 3)
            firstRead.countDown()
            assertTrue(source.awaitCompleted(MailAction.UNREAD))
            assertTrue(source.awaitCompleted(MailAction.READ, count = 2))
        }

        assertEquals(MailAction.UNREAD, source.completed.last())
    }

    /** The row menu's unread is ordered after a read the detail screen left in flight. */
    @Test
    fun rowMenuUnreadLandsAfterAPendingRead() {
        val heldRead = CountDownLatch(1)
        source.readGates.add(heldRead)
        ActivityScenario.launch<EmailDetailActivity>(detailIntent()).use { }

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(INBOX, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(row(INBOX, "read")))
            }
            scenario.chooseFromRowMenu(context.getString(R.string.action_mark_unread))
            source.awaitCompleted(MailAction.UNREAD, seconds = 3)
            heldRead.countDown()
            assertTrue(source.awaitCompleted(MailAction.UNREAD))
            assertTrue(source.awaitCompleted(MailAction.READ))
        }

        assertEquals(listOf(MailAction.READ, MailAction.UNREAD), source.completed.toList())
    }

    /** A completion for INBOX `42` must not repaint Archive's `42`, still on screen while the INBOX
     *  refresh is pending after a switch back. */
    @Test
    fun aRowMenuCompletionRepaintsOnlyItsOwnFolder() {
        val heldUnread = CountDownLatch(1)
        source.unreadGates.add(heldUnread)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(INBOX, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(row(INBOX, "read")))
            }
            scenario.chooseFromRowMenu(context.getString(R.string.action_mark_unread))
            scenario.onActivity { activity ->
                activity.setFolderForTest(ARCHIVE, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(row(ARCHIVE, "read")))
                activity.setFolderForTest(INBOX, KeywordTabs.ALL)
            }
            heldUnread.countDown()
            assertTrue(source.awaitCompleted(MailAction.UNREAD))
            onIdle()

            scenario.onActivity { activity ->
                assertEquals("read", activity.allEmailsForTest().single { it.folder == ARCHIVE }.status)
            }
        }
    }

    private companion object {
        const val ID = "42"
        // Folders no launch refresh is fetching, so nothing repaints the list under the test.
        const val INBOX = "MarkUnreadTestInbox"
        const val ARCHIVE = "MarkUnreadTestArchive"
    }
}
