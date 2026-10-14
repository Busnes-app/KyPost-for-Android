package org.kysecurity.mail.ui

import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailRuntime

/** A refresh that throws on the IO thread ends in the error state, not a dead process. */
@RunWith(AndroidJUnit4::class)
class InboxRefreshFailureTest {

    private val source = FakeMailSource()

    @Before
    fun installRelay() {
        MailRuntime.invalidate()
        source.inbox = { throw IllegalStateException("simulated failure") }
        MailRuntime.sourceForTest = source
    }

    @After
    fun releaseRelay() {
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    @Test
    fun aThrowingRefreshClearsTheLoadingState() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.refreshForTest()
            }
            val deadline = System.nanoTime() + 10_000_000_000L
            while (true) {
                var settled = false
                scenario.onActivity { settled = it.findViewById<View>(R.id.loadingOverlay).visibility == View.GONE }
                if (settled) break
                assertTrue("the loading state never cleared", System.nanoTime() < deadline)
                Thread.sleep(50)
            }
        }
    }

    private companion object {
        const val FOLDER = "RefreshFailureTestInbox"
    }
}
