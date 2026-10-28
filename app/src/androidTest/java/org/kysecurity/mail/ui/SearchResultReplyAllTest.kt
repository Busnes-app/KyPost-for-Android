package org.kysecurity.mail.ui

import android.app.Instrumentation
import android.content.Intent
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.Email
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.afterSplash

/** Search results are never written to Room, so the row's own To/Cc are the only copy there is.
 *  Opening one must keep them, or Reply All answers the sender alone. */
@RunWith(AndroidJUnit4::class)
class SearchResultReplyAllTest {

    /** Records and blocks the composer launch, so the test reads the intent Reply All built. */
    private class ComposeLaunches : Instrumentation.ActivityMonitor() {
        private val internalCompose = ComposeActivity
            .internalIntent(InstrumentationRegistry.getInstrumentation().targetContext).component?.className

        @Volatile var to: String? = null
        val launched = java.util.concurrent.CountDownLatch(1)
        override fun onStartActivity(intent: Intent): Instrumentation.ActivityResult? {
            // Reply All opens the in-app compose entry, the only one that reads EXTRA_TO.
            if (intent.component?.className != internalCompose) return null
            to = intent.getStringExtra(ComposeActivity.EXTRA_TO)
            launched.countDown()
            return Instrumentation.ActivityResult(0, null)
        }
    }

    @After
    fun releaseRuntime() {
        MailRuntime.invalidate()
    }

    @Test
    fun replyAllToAnUncachedSearchResultKeepsItsRecipients() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val result = Email(
            id = "search-only-171",
            subject = "Quarterly numbers",
            sender = "Alice <alice@example.com>",
            preview = "see attached",
            folder = "INBOX",
            sentTo = "me@example.com, bob@example.com",
            cc = "carol@example.com",
        )
        val detail = instrumentation.addMonitor(EmailDetailActivity::class.java.name, null, false)
        val compose = ComposeLaunches().also { instrumentation.addMonitor(it) }
        try {
            ActivityScenario.launch(InboxActivity::class.java).afterSplash().use { scenario ->
                scenario.onActivity { inbox ->
                    inbox.setFolderForTest("INBOX", KeywordTabs.ALL)
                    inbox.beginSearchForTest("numbers")
                    inbox.applySearchResults("numbers", "INBOX", MailOutcome.Success(listOf(result)))
                }
                instrumentation.waitForIdleSync()
                scenario.onActivity { inbox ->
                    val list = inbox.findViewById<RecyclerView>(R.id.recyclerViewInbox)
                    list.findViewHolderForAdapterPosition(0)!!.itemView.performClick()
                }
                val opened = instrumentation.waitForMonitorWithTimeout(detail, 10_000)
                assertNotNull("the search result never opened", opened)

                onView(withId(R.id.actionReplyAll)).perform(click())

                assertTrue("Reply All never opened the composer", compose.launched.await(10, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(
                    listOf("alice@example.com", "me@example.com", "bob@example.com", "carol@example.com"),
                    compose.to.orEmpty().split(",").map { it.trim() },
                )
                opened?.finish()
            }
        } finally {
            instrumentation.removeMonitor(detail)
            instrumentation.removeMonitor(compose)
        }
    }
}
