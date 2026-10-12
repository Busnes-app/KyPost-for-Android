package org.kysecurity.mail.ui

import android.view.View
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * An IMAP UID is unique only within one mailbox, so INBOX and Archive can both hold `42`. Work the
 * inbox defers — a swipe's mutation, a refresh's rows — must therefore carry the folder it was
 * started for. Re-reading the Activity's `currentFolder` when the work lands deletes, or paints,
 * the wrong mailbox.
 */
@RunWith(AndroidJUnit4::class)
class InboxFolderOwnershipTest {

    private fun email(id: String, folder: String) = Email(
        id = id,
        subject = "Subject $id",
        sender = "sender@example.com",
        preview = "preview",
        folder = folder,
    )

    @Test
    fun aSwipeMutatesTheRowsFolderEvenWhenTheScreenHasMovedOn() {
        val observed = arrayOfNulls<String>(1)
        val ran = CountDownLatch(1)

        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            // One block: the swipe and the folder switch must not be separated by a main-loop
            // turn, or the launch refresh could reset the list between them.
            scenario.onActivity { activity ->
                activity.rowActionObserverForTest = { _, folder ->
                    observed[0] = folder
                    ran.countDown()
                }
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("42", "INBOX")))

                // Swipe the INBOX row, then move to Archive before the worker can get to it. The
                // regression: the queued task re-read currentFolder and deleted Archive UID 42.
                activity.submitDeleteForTest(email("42", "INBOX"))
                activity.setFolderForTest("Archive", KeywordTabs.ALL)
            }

            assertEquals("the swipe action never ran", true, ran.await(10, TimeUnit.SECONDS))
            assertEquals("INBOX", observed[0])

            scenario.onActivity { it.rowActionObserverForTest = null }
        }
    }

    @Test
    fun aRefreshThatFinishesAfterAFolderSwitchDoesNotPaintItsRows() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("Archive", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("7", "Archive")))

                // The completion of a refresh that was started while INBOX was on screen.
                activity.applyRefreshedEmails(
                    folder = "INBOX",
                    emails = listOf(email("42", "INBOX")),
                    isFinal = true,
                    errorMessage = null,
                )

                assertEquals(listOf("7"), activity.allEmailsForTest().map { it.id })
            }
        }
    }

    /** Until the new folder loads, its title must not sit over the old folder's rows. */
    @Test
    fun aFolderSwitchClearsTheOldFoldersRowsAtOnce() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("42", "INBOX")))

                activity.switchFolderForTest("Archive")

                assertEquals(emptyList<String>(), activity.allEmailsForTest().map { it.id })
                assertEquals(0, activity.findViewById<RecyclerView>(R.id.recyclerViewInbox).adapter!!.itemCount)
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.loadingOverlay).visibility)
            }
        }
    }

    @Test
    fun aRefreshForTheFolderOnScreenStillPaints() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("Archive", KeywordTabs.ALL)
                activity.setEmailsForTest(emptyList())

                activity.applyRefreshedEmails(
                    folder = "Archive",
                    emails = listOf(email("7", "Archive")),
                    isFinal = true,
                    errorMessage = null,
                )

                assertEquals(listOf("7"), activity.allEmailsForTest().map { it.id })
            }
        }
    }
}
