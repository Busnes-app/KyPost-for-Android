package org.kysecurity.mail.ui

import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.swipeDown
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailRuntime

/** "No messages" is a claim about the server. Only a refresh that just succeeded can make it. */
@RunWith(AndroidJUnit4::class)
class InboxEmptyStateTest {

    @After
    fun releaseRuntime() {
        MailRuntime.invalidate()
    }

    private fun InboxActivity.emptyVisibility() = findViewById<View>(R.id.inboxEmpty).visibility

    private fun InboxActivity.confirmEmpty() {
        setFolderForTest("INBOX", KeywordTabs.ALL)
        applyRefreshedEmails("INBOX", emptyList(), isFinal = true, errorMessage = null, refreshedAt = 1L)
        assertEquals(View.VISIBLE, emptyVisibility())
    }

    @Test
    fun aFailedRefreshAfterAnEmptyOneHidesTheEmptyState() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.confirmEmpty()
                activity.applyRefreshedEmails("INBOX", emptyList(), isFinal = true, errorMessage = "offline", refreshedAt = null)
                assertEquals(View.GONE, activity.emptyVisibility())
            }
        }
    }

    /** This device is unpaired, so the pull's own fetch fails too: hidden either way. */
    @Test
    fun aPullToRefreshHidesTheEmptyState() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { it.confirmEmpty() }
            onView(withId(R.id.inboxSwipeRefresh)).perform(swipeDown())
            scenario.onActivity { assertEquals(View.GONE, it.emptyVisibility()) }
        }
    }
}
