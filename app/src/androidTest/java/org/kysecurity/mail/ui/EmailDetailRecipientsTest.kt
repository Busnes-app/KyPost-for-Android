package org.kysecurity.mail.ui

import android.content.Intent
import android.view.View
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailRuntime

/** Issue #39: the detail view named the sender but never who the message was sent to. */
@RunWith(AndroidJUnit4::class)
class EmailDetailRecipientsTest {

    @After
    fun releaseRuntime() {
        MailRuntime.invalidate()
    }

    @Test
    fun toAndCcAreListedUnderTheSender() {
        launch().use { scenario ->
            scenario.onActivity { activity ->
                assertFalse("test device must have the app unlocked", activity.isFinishing)
                activity.showRecipients(listOf("me@example.com", "team@example.com"), listOf("boss@example.com"))

                val view = activity.findViewById<TextView>(R.id.emailRecipients)
                assertEquals(View.VISIBLE, view.visibility)
                assertEquals("To: me@example.com, team@example.com\nCc: boss@example.com", view.text.toString())
            }
        }
    }

    @Test
    fun aRowWithoutRecipientsShowsNoEmptyLabel() {
        launch().use { scenario ->
            scenario.onActivity { activity ->
                activity.showRecipients(emptyList(), emptyList())

                assertEquals(View.GONE, activity.findViewById<TextView>(R.id.emailRecipients).visibility)
            }
        }
    }

    private fun launch(): ActivityScenario<EmailDetailActivity> {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        return ActivityScenario.launch(Intent(context, EmailDetailActivity::class.java).putExtra("email_preview", "body"))
    }
}
