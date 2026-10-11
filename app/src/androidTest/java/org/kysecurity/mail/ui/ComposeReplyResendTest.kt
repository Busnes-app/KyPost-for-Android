package org.kysecurity.mail.ui

import android.content.DialogInterface
import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onIdle
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ReplyRef
import org.kysecurity.mail.ReplyThreadHandoff
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.MailSendOutcome

/** A reply the relay refuses to thread, against a relay the test controls: what each confirmed
 *  re-send carries, in either dialog order, and that cancel and a double tap send nothing extra. */
@RunWith(AndroidJUnit4::class)
class ComposeReplyResendTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun installRelay() {
        ComposeDraftCache.clear()
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
    }

    @After
    fun releaseRelay() {
        ComposeDraftCache.clear()
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    private fun replyIntent() = Intent(context, ComposeActivity::class.java)
        .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
        .putExtra(ComposeActivity.EXTRA_SUBJECT, "Re: hi")
        .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<p>hello</p>")
        .putExtra(ComposeActivity.EXTRA_REPLY_TOKEN, ReplyThreadHandoff.put(ReplyRef("42", "INBOX")))

    private val refused: MailOutcome<MailSendOutcome> =
        MailOutcome.ReplyThreadingRefused("the message being replied to was not found; nothing was sent")
    private val keyless: MailOutcome<MailSendOutcome> =
        MailOutcome.PickupFallbackNeeded(listOf("bob@example.com"), "no key")
    private val sent: MailOutcome<MailSendOutcome> = MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))

    private fun waitFor(what: String, condition: () -> Boolean) {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (!condition()) {
            assertTrue("timed out waiting for $what", System.nanoTime() < deadline)
            Thread.sleep(50)
        }
    }

    private fun ActivityScenario<ComposeActivity>.send() {
        waitFor("the editor to hold the body") {
            var ready = false
            onActivity { ready = it.bodyReadyForTest() }
            ready
        }
        onActivity { it.sendForTest() }
    }

    /** Waits for the next dialog, then presses [button] on it [taps] times in one main-loop turn. */
    private fun ActivityScenario<ComposeActivity>.answerDialog(button: Int, taps: Int = 1) {
        waitFor("a dialog") {
            var showing = false
            onActivity { showing = it.activeDialogForTest()?.isShowing == true }
            showing
        }
        onActivity { activity ->
            val target = activity.activeDialogForTest()!!.getButton(button)
            repeat(taps) { target.performClick() }
        }
        onIdle()
    }

    private fun MailDraft.isThreaded() = replyToMessageId != null || replyToMailbox != null

    @Test
    fun refusalThenPickupThenSuccessSendsThreeRequestsEndingUnthreadedWithConsent() {
        source.sendOutcomes.addAll(listOf(refused, keyless, sent))
        ActivityScenario.launch<ComposeActivity>(replyIntent()).use { scenario ->
            scenario.send()
            scenario.answerDialog(DialogInterface.BUTTON_POSITIVE)
            scenario.answerDialog(DialogInterface.BUTTON_POSITIVE)
            waitFor("three sends") { source.sends.size == 3 }
        }

        val (first, second, third) = source.sends
        assertEquals("42", first.replyToMessageId)
        assertEquals("INBOX", first.replyToMailbox)
        assertFalse(second.isThreaded())
        assertFalse(second.allowPickupFallback)
        assertFalse(third.isThreaded())
        assertTrue(third.allowPickupFallback)
    }

    @Test
    fun pickupThenRefusalKeepsTheConsentOnTheUnthreadedResend() {
        source.sendOutcomes.addAll(listOf(keyless, refused, sent))
        ActivityScenario.launch<ComposeActivity>(replyIntent()).use { scenario ->
            scenario.send()
            scenario.answerDialog(DialogInterface.BUTTON_POSITIVE)
            scenario.answerDialog(DialogInterface.BUTTON_POSITIVE)
            waitFor("three sends") { source.sends.size == 3 }
        }

        val (first, second, third) = source.sends
        assertTrue(first.isThreaded())
        assertTrue(second.isThreaded())
        assertTrue(second.allowPickupFallback)
        assertFalse(third.isThreaded())
        assertTrue(third.allowPickupFallback)
    }

    @Test
    fun cancellingTheUnthreadedOfferSendsNothingMore() {
        source.sendOutcomes.add(refused)
        ActivityScenario.launch<ComposeActivity>(replyIntent()).use { scenario ->
            scenario.send()
            scenario.answerDialog(DialogInterface.BUTTON_NEGATIVE)
            Thread.sleep(1_000)

            assertEquals(1, source.sends.size)
            scenario.onActivity { assertFalse(it.isFinishing) }
        }
    }

    /** Two taps land before the dialog dismisses; only one re-send may leave. */
    @Test
    fun aDoubleTapOnSendAnywaySendsOnce() {
        source.sendOutcomes.add(refused)
        ActivityScenario.launch<ComposeActivity>(replyIntent()).use { scenario ->
            scenario.send()
            scenario.answerDialog(DialogInterface.BUTTON_POSITIVE, taps = 2)
            waitFor("the re-send") { source.sends.size >= 2 }
            Thread.sleep(1_000)

            assertEquals(2, source.sends.size)
            assertNull(source.sends[1].replyToMessageId)
            source.sendOutcomes.add(sent)
        }
    }
}
