package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
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
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.MailSettings
import org.kysecurity.mail.mail.Conversation
import org.kysecurity.mail.mail.MailAccount
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime

/** Conversations belong to the account they were fetched for, in the same Activity too. */
@RunWith(AndroidJUnit4::class)
class InboxConversationAccountTest {

    private val settings = MailSettings(InstrumentationRegistry.getInstrumentation().targetContext)
    private var conversationsWere = true

    @Before
    fun groupConversations() {
        conversationsWere = settings.conversations()
        settings.setConversations(true)
    }

    @After
    fun restore() {
        settings.setConversations(conversationsWere)
        MailRuntime.invalidate()
    }

    private fun email(id: String, subject: String, folder: String = FOLDER, at: String = "2026-11-01T0$id:00:00Z") =
        Email(id = id, subject = subject, sender = "sender@example.com", preview = "", atUtc = at, folder = folder)

    /** The second account's ids repeat the first's, and its server cannot group conversations. */
    @Test
    fun aNewAccountsMessagesNeverShowThePreviousAccountsReplies() {
        val reply = email("9", REPLY_SUBJECT, folder = "Sent")
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.setShownAccountForTest(FIRST)
                activity.setEmailsForTest(listOf(email("3", "First three"), email("1", "First one")))
                activity.applyConversationsForTest(
                    MailOutcome.Success(listOf(Conversation(THREAD, listOf("1", "3"), listOf(reply)))),
                    expand = setOf(THREAD),
                )
                assertTrue(
                    "the first account's reply is shown under it",
                    activity.shownEmailsForTest().any { it.subject == REPLY_SUBJECT },
                )

                // Replaced in the same Activity: same ids, and the new server has no route.
                activity.setShownAccountForTest(SECOND)
                activity.setEmailsForTest(listOf(email("3", "Second three"), email("1", "Second one")))
                activity.applyConversationsForTest(MailOutcome.BadRequest("Not supported"), expand = setOf(THREAD))
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                val shown = activity.shownEmailsForTest()
                assertFalse("a previous-account reply is shown", shown.any { it.subject == REPLY_SUBJECT })
                assertEquals("the previous account's grouping is shown", listOf("Second three", "Second one"), shown.map { it.subject })
            }
        }
    }

    private companion object {
        const val FOLDER = "Archive/ConversationAccountTest"
        const val THREAD = "thread-1"
        const val REPLY_SUBJECT = "Previous account reply"
        val FIRST = MailAccount(subscriberId = "first", serverUrl = "https://relay.example.test")
        val SECOND = MailAccount(subscriberId = "second", serverUrl = "https://relay.example.test")
    }
}
