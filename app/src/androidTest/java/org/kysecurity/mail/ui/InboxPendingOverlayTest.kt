package org.kysecurity.mail.ui

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.data.EmailEntity
import org.kysecurity.mail.mail.MailRuntime
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

@RunWith(AndroidJUnit4::class)
class InboxPendingOverlayTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val dao get() = DataRuntime.graph(context).database.emailDao()

    /** The database stays with the suite; only the mail graph this fixture built is released. */
    @After
    fun releaseTheMailGraph() {
        dao.deleteById("42", FOLDER)
        MailRuntime.invalidate()
    }

    /** Back from the message with the network slow: the row must lose bold before the fetch returns. */
    @Test
    fun aMessageBeingMarkedReadShowsReadBeforeTheRefreshAnswers() {
        dao.upsertAll(listOf(EmailEntity(messageId = "42", folder = FOLDER, sender = "a@example.com", subject = "s", sourceMode = "relay")))
        val release = CountDownLatch(1)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity {
                it.setFolderForTest(FOLDER, KeywordTabs.ALL)
                it.setEmailsForTest(listOf(Email(id = "42", subject = "s", sender = "a@example.com", preview = "", folder = FOLDER)))
                it.beforeNetworkRefreshForTest = { folder -> if (folder == FOLDER) release.await(10, TimeUnit.SECONDS) }
            }
            // What the detail screen does when it opens the message.
            val repository = MailRuntime.graph(context).repository
            val claim = repository.beginRead("42", FOLDER)

            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.moveToState(Lifecycle.State.RESUMED)

            try {
                assertTrue("the read overlay waited for the network", awaitStatus(scenario, "read"))
            } finally {
                release.countDown()
                scenario.onActivity { it.beforeNetworkRefreshForTest = null }
                repository.abandon(claim)
            }
        }
    }

    /** After INBOX 42 fails, a Retry tapped from Archive must not hide Archive's own 42. */
    @Test
    fun aRetryFromAnotherFolderLeavesThatFoldersRowAlone() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(Email(id = "42", subject = "a", sender = "s", preview = "", folder = FOLDER)))

                // The Retry re-submits the original INBOX row.
                activity.submitDeleteForTest(Email(id = "42", subject = "i", sender = "s", preview = "", folder = "INBOX"))

                assertEquals(listOf("42"), activity.allEmailsForTest().map { it.id })
            }
        }
    }

    private fun awaitStatus(scenario: ActivityScenario<InboxActivity>, status: String): Boolean {
        val deadline = System.currentTimeMillis() + 5_000
        while (System.currentTimeMillis() < deadline) {
            var current: String? = null
            scenario.onActivity { current = it.allEmailsForTest().firstOrNull { e -> e.id == "42" }?.status }
            if (current == status) return true
            Thread.sleep(100)
        }
        return false
    }

    private companion object {
        const val FOLDER = "Archive/PendingOverlayTest"
    }
}
