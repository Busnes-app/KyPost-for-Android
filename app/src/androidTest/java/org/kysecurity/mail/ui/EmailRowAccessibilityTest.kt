package org.kysecurity.mail.ui

import android.widget.FrameLayout
import androidx.core.view.ViewCompat
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.After
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.Email
import org.kysecurity.mail.EmailAdapter
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.R

/** TalkBack users see neither the unread dot nor the swipes, so the row has to say and offer both. */
@RunWith(AndroidJUnit4::class)
class EmailRowAccessibilityTest {

    /** The database stays with the suite; only the mail graph the Activity built is released. */
    @After
    fun releaseTheMailGraph() {
        MailRuntime.invalidate()
    }

    private fun email(status: String, attachments: Boolean) = Email(
        id = "1", subject = "Invoice", sender = "Bob <bob@example.com>", preview = "",
        status = status, hasAttachments = attachments,
    )

    @Test
    fun theRowSpeaksItsStateAndOffersArchiveAndDelete() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val acted = mutableListOf<String>()
                val adapter = EmailAdapter(
                    listOf(email("unread", attachments = true)),
                    rowActions = listOf(
                        R.string.action_archive to { e: Email -> acted += "archive:${e.id}" },
                        R.string.action_delete to { e: Email -> acted += "delete:${e.id}" },
                    ),
                )
                val holder = adapter.onCreateViewHolder(FrameLayout(activity), 0)
                adapter.onBindViewHolder(holder, 0)
                val row = holder.itemView

                val spoken = row.contentDescription.toString()
                assertTrue(spoken, spoken.startsWith("Unread"))
                assertTrue(spoken, spoken.contains("Invoice"))
                assertTrue(spoken, spoken.contains("has attachments"))

                // A rebind must replace the actions, not stack a second pair.
                adapter.updateEmails(listOf(email("read", attachments = false)))
                adapter.onBindViewHolder(holder, 0)
                val reread = row.contentDescription.toString()
                assertFalse(reread, reread.contains("Unread"))
                assertFalse(reread, reread.contains("has attachments"))

                val actions = row.createAccessibilityNodeInfo().actionList.filter { it.label != null }
                assertEquals(listOf("Archive", "Delete"), actions.map { it.label.toString() })
                actions.forEach { ViewCompat.performAccessibilityAction(row, it.id, null) }
                assertEquals(listOf("archive:1", "delete:1"), acted)
            }
        }
    }
}
