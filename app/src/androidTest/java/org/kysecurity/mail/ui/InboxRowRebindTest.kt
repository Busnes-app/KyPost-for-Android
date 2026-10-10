package org.kysecurity.mail.ui

import android.widget.FrameLayout
import android.widget.TextView
import androidx.lifecycle.Lifecycle
import androidx.recyclerview.widget.RecyclerView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.Email
import org.kysecurity.mail.EmailAdapter
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordSettings
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R

@RunWith(AndroidJUnit4::class)
class InboxRowRebindTest {

    /** The database stays with the suite; only the mail graph the Activity built is released. */
    @After
    fun releaseTheMailGraph() {
        MailRuntime.invalidate()
    }

    private val keywordSettings =
        KeywordSettings(InstrumentationRegistry.getInstrumentation().targetContext)

    @Before
    fun showTheKeyword() {
        keywordSettings.rememberKeywords(setOf(KEYWORD))
        keywordSettings.setKeywordVisible(KEYWORD, true)
    }

    @After
    fun hideTheKeyword() {
        keywordSettings.setKeywordVisible(KEYWORD, false)
    }

    private fun email(status: String) = Email(
        id = "1", subject = "Subject", sender = "sender@example.com", preview = "",
        status = status, keywords = setOf(KEYWORD), folder = FOLDER,
    )

    /** setTypeface(current, NORMAL) keeps an already-bold typeface, so a recycled row stayed bold. */
    @Test
    fun aRowReboundAsReadIsNotBold() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val adapter = EmailAdapter(listOf(email("unread")))
                val holder = adapter.onCreateViewHolder(FrameLayout(activity), 0)
                val subject = holder.itemView.findViewById<TextView>(R.id.textViewSubject)

                adapter.onBindViewHolder(holder, 0)
                assertTrue(subject.typeface.isBold)

                adapter.updateEmails(listOf(email("read")))
                adapter.onBindViewHolder(holder, 0)
                assertFalse(subject.typeface.isBold)
            }
        }
    }

    @Test
    fun aTabWhoseMailWasReadIsNotBold() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.applyRefreshedEmails(FOLDER, listOf(email("unread")), isFinal = true, errorMessage = null)
                val chip = activity.findViewById<ChipGroup>(R.id.keywordChipGroup)
                    .let { group -> (0 until group.childCount).map { group.getChildAt(it) as Chip } }
                    .first { it.text == KEYWORD }
                assertTrue(chip.typeface.isBold)

                activity.applyRefreshedEmails(FOLDER, listOf(email("read")), isFinal = true, errorMessage = null)
                assertFalse(chip.typeface.isBold)
            }
        }
    }

    /** The theme is unchanged across a resume (a change recreates), so nothing needs rebinding. */
    @Test
    fun resumingDoesNotRebindEveryRow() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            var fullRebinds = 0
            scenario.onActivity { activity ->
                activity.setFolderForTest(FOLDER, KeywordTabs.ALL)
                activity.setEmailsForTest(listOf(email("read")))
                activity.findViewById<RecyclerView>(R.id.recyclerViewInbox).adapter!!
                    .registerAdapterDataObserver(object : RecyclerView.AdapterDataObserver() {
                        override fun onChanged() { fullRebinds++ }
                    })
            }

            scenario.moveToState(Lifecycle.State.STARTED)
            scenario.moveToState(Lifecycle.State.RESUMED)

            scenario.onActivity { assertEquals(0, fullRebinds) }
        }
    }

    private companion object {
        const val KEYWORD = "RebindTest"
        const val FOLDER = "Archive/RebindTest"
    }
}
