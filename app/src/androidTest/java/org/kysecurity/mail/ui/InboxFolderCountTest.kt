package org.kysecurity.mail.ui

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
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.data.EmailEntity
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.MailRuntime
import java.util.concurrent.CountDownLatch

/** The folder picker's unread counts follow a confirmed action even when it finishes after the
 *  user has moved to another folder. */
@RunWith(AndroidJUnit4::class)
class InboxFolderCountTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val dao get() = DataRuntime.graph(context).database.emailDao()

    @Before
    fun installRelay() {
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
        dao.upsertAll(listOf(EmailEntity(messageId = ID, folder = FOLDER, sender = "a", subject = "s", sourceMode = "relay")))
    }

    @After
    fun releaseRelay() {
        dao.deleteById(ID, FOLDER)
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    private fun ActivityScenario<InboxActivity>.awaitCount(folder: String, expected: Int) {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (true) {
            var count = -1
            onActivity { count = it.unreadByFolderForTest()[folder] ?: 0 }
            if (count == expected) return
            assertTrue("$folder count stayed $count, expected $expected", System.nanoTime() < deadline)
            Thread.sleep(50)
        }
    }

    @Test
    fun aMarkReadThatFinishesAfterAFolderSwitchStillCountsForItsFolder() {
        val heldRead = CountDownLatch(1)
        source.readGates.add(heldRead)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.refreshForTest()
            }
            scenario.awaitCount(FOLDER, 1)
            scenario.onActivity { activity ->
                activity.setEmailsForTest(
                    listOf(Email(id = ID, subject = "s", sender = "a", preview = "", folder = FOLDER, status = "unread")),
                )
            }
            onIdle()
            scenario.onActivity { activity ->
                activity.findViewById<RecyclerView>(R.id.recyclerViewInbox)
                    .findViewHolderForAdapterPosition(0)!!.itemView.performLongClick()
            }
            onView(withText(context.getString(R.string.action_mark_read))).inRoot(isPlatformPopup()).perform(click())

            // Move on, and let the other folder's refresh land, before the read completes.
            scenario.onActivity { activity ->
                activity.setFolderForTest(OTHER, KeywordTabs.ALL)
                activity.refreshForTest()
            }
            val deadline = System.nanoTime() + 10_000_000_000L
            while (true) {
                var painted = false
                scenario.onActivity { painted = it.allEmailsForTest().isEmpty() }
                if (painted) break
                assertTrue("the other folder's refresh never landed", System.nanoTime() < deadline)
                Thread.sleep(50)
            }
            heldRead.countDown()
            assertTrue(source.awaitCompleted(MailAction.READ))

            scenario.awaitCount(FOLDER, 0)
        }
    }

    private companion object {
        const val ID = "42"
        const val FOLDER = "FolderCountTestInbox"
        const val OTHER = "FolderCountTestJunk"
    }
}
