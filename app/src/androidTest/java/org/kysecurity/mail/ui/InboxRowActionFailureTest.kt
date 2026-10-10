package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/** A swipe hides the row at once; if the server refuses, the row must come back where it was. */
@RunWith(AndroidJUnit4::class)
class InboxRowActionFailureTest {

    private fun email(id: String) =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = FOLDER)

    @Test
    fun aFailedSwipeActionPutsTheRowBackInPlace() {
        val shown = CountDownLatch(1)
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.rowActionFailureShownForTest = { shown.countDown() }
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2"), email("3")))

                // The test device is not paired, so the relay call fails (Unauthorized).
                activity.submitDeleteForTest(email("2"))

                assertEquals(listOf("1", "3"), activity.allEmailsForTest().map { it.id })
            }

            assertTrue("the failure was never shown", shown.await(10, TimeUnit.SECONDS))
            scenario.onActivity { activity ->
                assertEquals(listOf("1", "2", "3"), activity.allEmailsForTest().map { it.id })
                activity.rowActionFailureShownForTest = null
            }
        }
    }

    private companion object {
        const val FOLDER = "Archive/RowActionFailureTest"
    }
}
