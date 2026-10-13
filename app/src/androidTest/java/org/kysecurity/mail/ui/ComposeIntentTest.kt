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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ForwardAttachmentHandoff
import org.kysecurity.mail.mail.OutgoingAttachment
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.R
import org.kysecurity.mail.RecipientInputView
import org.kysecurity.mail.ReplyRef

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
    fun externalSendDoesNotTakeForwardedAttachments() {
        ForwardAttachmentHandoff.put(listOf(OutgoingAttachment("left.txt", "text/plain", byteArrayOf(1))))
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_SEND).apply {
            putExtra(Intent.EXTRA_TEXT, "Shared text")
            setType("text/plain")
            setClass(context, ComposeActivity::class.java)
        }

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(0, activity.findViewById<ChipGroup>(R.id.composeAttachmentsCard).childCount)
            }
        }
        assertTrue(ForwardAttachmentHandoff.take().isEmpty())
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

    @Test
    fun anInAppDraftEditCarriesItsRecipientsAndTheDraftToReplace() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_CC, "carol@example.com")
            .putExtra(ComposeActivity.EXTRA_BCC, "dan@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<p>draft</p>")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                assertEquals(listOf("carol@example.com"), activity.findViewById<RecipientInputView>(R.id.composeCcInput).recipientEmails())
                assertEquals(listOf("dan@example.com"), activity.findViewById<RecipientInputView>(R.id.composeBccInput).recipientEmails())
                assertEquals(ReplyRef("7", "Drafts"), activity.sourceDraftForTest())
                // The draft already has whatever signature it was written with.
                assertEquals("<p>draft</p>", activity.mirroredBodyHtmlForTest())
            }
        }
    }

    /** Naming a draft makes this screen delete it later; no other app may do that. */
    @Test
    fun anOutsideLaunchCannotNameADraftToDelete() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(Intent.ACTION_SEND).apply {
            putExtra(Intent.EXTRA_TEXT, "Shared text")
            putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
            putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")
            setType("text/plain")
            setClass(context, ComposeActivity::class.java)
        }

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity -> assertNull(activity.sourceDraftForTest()) }
        }
    }

    /** The exported activity, named directly with no action, is still not an in-app launch. */
    @Test
    fun anExplicitLaunchOfTheExportedScreenCannotNameADraftToDelete() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(context, ComposeActivity::class.java)
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity -> assertNull(activity.sourceDraftForTest()) }
        }
    }

    /** A process restart empties the attachment handoff; the draft that had them must stay. */
    @Test
    fun aDraftWhoseAttachmentsDidNotArriveIsNotReplaced() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ATTACHMENTS, 1)

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity -> assertNull(activity.sourceDraftForTest()) }
        }
    }

    @Test
    fun aRecreatedScreenStillKnowsWhichDraftItReplaces() {
        ComposeDraftCache.take()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
            .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.recreate()
            scenario.onActivity { activity -> assertEquals(ReplyRef("7", "Drafts"), activity.sourceDraftForTest()) }
        }
    }

    /** take() also unseals, so a later test's save() is not a no-op. */
    @After
    fun drainTheCache() {
        ComposeDraftCache.take()
    }
}
