package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposeSend
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.pgp.PgpComposeState

/** An edited draft is replaced, never lost: the old copy goes only once the new one has gone. */
@RunWith(AndroidJUnit4::class)
class ComposeDraftEditTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun installRelay() {
        ComposeDraftCache.clear()
        ComposeSend.resetForNewSession()
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
    }

    @After
    fun releaseRelay() {
        ComposeDraftCache.clear()
        ComposeSend.resetForNewSession()
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    private fun draftEdit() = ComposeActivity.internalIntent(context)
        .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
        .putExtra(ComposeActivity.EXTRA_SUBJECT, "Plans")
        .putExtra(ComposeActivity.EXTRA_BODY_HTML, "<p>draft</p>")
        .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_ID, "7")
        .putExtra(ComposeActivity.EXTRA_SOURCE_DRAFT_FOLDER, "Drafts")

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
        onActivity {
            it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false))
            it.sendForTest()
        }
    }

    @Test
    fun sendingTheEditDeletesTheOldDraft() {
        source.sendOutcomes.add(MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = "")))
        ActivityScenario.launch<ComposeActivity>(draftEdit()).use { scenario ->
            scenario.send()
            assertTrue("the old draft was not deleted", source.awaitCompleted(MailAction.DELETE))
        }
    }

    @Test
    fun aFailedSendKeepsTheOldDraft() {
        source.sendOutcomes.add(MailOutcome.UpstreamFailure("smtp down"))
        ActivityScenario.launch<ComposeActivity>(draftEdit()).use { scenario ->
            scenario.send()
            waitFor("the send") { source.sends.size == 1 }
            assertFalse("the old draft went with nothing to replace it", source.awaitCompleted(MailAction.DELETE, seconds = 2))
        }
    }
}
