package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.mail.MailAccount
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A row action belongs to the account it was created under; its result does not carry over. */
@RunWith(AndroidJUnit4::class)
class InboxRowActionAccountTest {

    private fun email(id: String) =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = FOLDER)

    @Test
    fun aFailedActionFromAnEarlierAccountOffersNoRetry() {
        val dropped = CountDownLatch(1)
        val shown = CountDownLatch(1)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.setShownAccountForTest(FIRST)
                activity.setEmailsForTest(listOf(email("1"), email("2"), email("3")))
                activity.rowActionDroppedForTest = { dropped.countDown() }
                activity.rowActionFailureShownForTest = { shown.countDown() }
                // The account is replaced while the delete is outstanding.
                activity.rowActionObserverForTest = { _, _ -> activity.setShownAccountForTest(SECOND) }

                // The test device is not paired, so the delete fails.
                activity.submitDeleteForTest(email("2"))
            }

            assertTrue("the outcome was never handled", dropped.await(10, TimeUnit.SECONDS))
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                assertEquals("a Retry was offered", 1L, shown.count)
                assertEquals(listOf("1", "3"), activity.allEmailsForTest().map { it.id })
                activity.rowActionDroppedForTest = null
                activity.rowActionFailureShownForTest = null
                activity.rowActionObserverForTest = null
            }
        }
    }

    private companion object {
        const val FOLDER = "Archive/RowActionAccountTest"
        val FIRST = MailAccount(subscriberId = "first", serverUrl = "https://relay.example.test")
        val SECOND = MailAccount(subscriberId = "second", serverUrl = "https://relay.example.test")
    }
}
