package org.kysecurity.mail.ui

import android.view.View
import androidx.appcompat.widget.SearchView
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.pressImeActionButton
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.withContentDescription
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.Email
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime

/** Search results replace the folder list only while their query, in their folder, is on screen. */
@RunWith(AndroidJUnit4::class)
class InboxSearchTest {

    @After
    fun releaseRuntime() {
        MailRuntime.invalidate()
    }

    private fun email(id: String, folder: String = "INBOX") =
        Email(id = id, subject = "Subject $id", sender = "sender@example.com", preview = "", folder = folder)

    private fun withInbox(block: (InboxActivity) -> Unit) {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2")))
                block(activity)
            }
        }
    }

    @Test
    fun resultsReplaceTheListUntilTheSearchEnds() = withInbox { activity ->
        activity.beginSearchForTest("invoice")
        activity.applySearchResults("invoice", "INBOX", MailOutcome.Success(listOf(email("9"))))
        assertEquals(listOf("9"), activity.shownEmailsForTest().map { it.id })

        activity.exitSearchForTest()
        assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
    }

    @Test
    fun resultsForASupersededQueryAreDropped() = withInbox { activity ->
        activity.beginSearchForTest("invoice 2026")
        activity.applySearchResults("invoice", "INBOX", MailOutcome.Success(listOf(email("9"))))
        assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
    }

    @Test
    fun resultsForAFolderNoLongerOnScreenAreDropped() = withInbox { activity ->
        activity.beginSearchForTest("invoice")
        activity.setFolderForTest("Archive", KeywordTabs.ALL)
        activity.applySearchResults("invoice", "INBOX", MailOutcome.Success(listOf(email("9"))))
        assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
    }

    @Test
    fun aFailedSearchKeepsTheFolderList() = withInbox { activity ->
        activity.beginSearchForTest("invoice")
        activity.applySearchResults("invoice", "INBOX", MailOutcome.UpstreamFailure("down"))
        assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
    }

    @Test
    fun aFailedReplacementSearchRestoresTheFolderList() = withInbox { activity ->
        activity.beginSearchForTest("invoice")
        activity.applySearchResults("invoice", "INBOX", MailOutcome.Success(listOf(email("9"))))
        activity.beginSearchForTest("receipt")
        activity.applySearchResults("receipt", "INBOX", MailOutcome.UpstreamFailure("down"))
        assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
    }

    /** Drives the real SearchView. This device is unpaired, so each submitted search fails fast. */
    private fun submitInSearchView(query: String) {
        onView(withContentDescription("Search mail")).perform(click())
        onView(isAssignableFrom(SearchView.SearchAutoComplete::class.java))
            .perform(replaceText(query), pressImeActionButton())
    }

    @Test
    fun keywordChipsHideAsSoonAsASearchIsSubmitted() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2")))
            }
            submitInSearchView("invoice")
            scenario.onActivity { activity ->
                assertEquals(View.GONE, activity.findViewById<View>(R.id.keywordChipScroll).visibility)
            }
        }
    }

    @Test
    fun editingTheQueryDropsTheSubmittedSearchesResults() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("1"), email("2")))
            }
            submitInSearchView("invoice")
            onView(isAssignableFrom(SearchView.SearchAutoComplete::class.java)).perform(replaceText(""))
            scenario.onActivity { activity ->
                // The submitted query's answer arriving after the text no longer shows it.
                activity.applySearchResults("invoice", "INBOX", MailOutcome.Success(listOf(email("9"))))
                assertEquals(listOf("1", "2"), activity.shownEmailsForTest().map { it.id })
            }
        }
    }
}
