package org.kysecurity.mail.ui

import android.content.Intent
import android.net.Uri
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.R
import org.kysecurity.mail.RecipientInputView

@RunWith(AndroidJUnit4::class)
class ComposeIntentTest {

    @Test
    fun mailtoUriIsParsed() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_SENDTO).apply {
            data = Uri.parse("mailto:bob%2Btag@example.com?subject=Hello%20%3D%20there&body=One%3Dtwo")
            setClass(context, ComposeActivity::class.java)
        }

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            onView(withId(R.id.composeSubjectField)).check(matches(withText("Hello = there")))
            scenario.onActivity { activity ->
                val toInput = activity.findViewById<RecipientInputView>(R.id.composeToInput)
                assertEquals(listOf("bob+tag@example.com"), toInput.recipientEmails())
            }
        }
    }

    @Test
    fun standardIntentExtrasAreParsed() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_SEND).apply {
            putExtra(Intent.EXTRA_EMAIL, arrayOf("alice@example.com"))
            putExtra(Intent.EXTRA_SUBJECT, "Standard Subject")
            putExtra(Intent.EXTRA_TEXT, "Standard Body")
            setType("text/plain")
            setClass(context, ComposeActivity::class.java)
        }

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            onView(withId(R.id.composeSubjectField)).check(matches(withText("Standard Subject")))
            scenario.onActivity { activity ->
                val toInput = activity.findViewById<RecipientInputView>(R.id.composeToInput)
                assertEquals(listOf("alice@example.com"), toInput.recipientEmails())
            }
        }
    }

    @Test
    fun externalSendReadsOnlyPublicExtras() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_SEND).apply {
            putExtra(Intent.EXTRA_EMAIL, arrayOf("alice@example.com"))
            putExtra(Intent.EXTRA_TEXT, "Shared text")
            putExtra(ComposeActivity.EXTRA_TO, "other@example.com")
            putExtra(ComposeActivity.EXTRA_BODY_HTML, "<b>marked</b>")
            setType("text/plain")
            setClass(context, ComposeActivity::class.java)
        }

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val body = activity.mirroredBodyHtmlForTest()
                assertTrue(body, body.contains("Shared text"))
                assertFalse(body, body.contains("<b>"))
                val toInput = activity.findViewById<RecipientInputView>(R.id.composeToInput)
                assertEquals(listOf("alice@example.com"), toInput.recipientEmails())
            }
        }
    }

    @Test
    fun explicitLaunchOfExportedComposeIgnoresHtmlExtra() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(context, ComposeActivity::class.java)
            .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<b>marked</b>")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertFalse(activity.mirroredBodyHtmlForTest().contains("<b>"))
            }
        }
    }

    @Test
    fun internalLaunchKeepsReplyHtml() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<blockquote>quoted</blockquote>")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(activity.mirroredBodyHtmlForTest().contains("<blockquote>quoted"))
                val toInput = activity.findViewById<RecipientInputView>(R.id.composeToInput)
                assertEquals(listOf("bob@example.com"), toInput.recipientEmails())
            }
        }
    }

    /** take() also unseals, so a later test's save() is not a no-op. */
    @After
    fun drainTheCache() {
        ComposeDraftCache.take()
    }
}
