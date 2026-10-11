package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.push.PushNotificationDispatcher

/** A notification tap is consumed once: a rotation afterwards must not hunt for it again. */
@RunWith(AndroidJUnit4::class)
class InboxNotificationRecreateTest {

    /** The database stays with the suite; only the mail graph the Activity built is released. */
    @After
    fun releaseTheMailGraph() {
        MailRuntime.invalidate()
    }

    private val notificationTap = Intent(
        InstrumentationRegistry.getInstrumentation().targetContext,
        InboxActivity::class.java,
    ).putExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID, "42")
        .putExtra(PushNotificationDispatcher.EXTRA_SENDER, "sender@example.com")

    @Test
    fun aRecreateDoesNotReopenTheNotifiedMessage() {
        ActivityScenario.launch<InboxActivity>(notificationTap).use { scenario ->
            scenario.onActivity {
                assertEquals("42", it.pendingMessageIdForTest())
                assertFalse(it.intent.hasExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID))
                // The user has since opened the message and moved on to another folder.
                it.clearPendingMessageForTest()
                it.setFolderForTest("Archive", KeywordTabs.ALL)
            }

            scenario.recreate()

            scenario.onActivity {
                assertNull(it.pendingMessageIdForTest())
                assertEquals("Archive", it.currentFolderForTest())
            }
        }
    }

    /** Returning to Inbox through navigation mid-hunt delivers an intent with no notification;
     *  the hunt for the notified message must carry on. */
    @Test
    fun anOrdinaryIntentDoesNotCancelAPendingHunt() {
        ActivityScenario.launch<InboxActivity>(notificationTap).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals("42", activity.pendingMessageIdForTest())

                InstrumentationRegistry.getInstrumentation()
                    .callActivityOnNewIntent(activity, Intent(activity, InboxActivity::class.java))

                assertEquals("42", activity.pendingMessageIdForTest())
            }
        }
    }
}
