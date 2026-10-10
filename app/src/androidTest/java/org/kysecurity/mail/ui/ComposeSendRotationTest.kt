package org.kysecurity.mail.ui

import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposeSend
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** A rotation mid-send must neither cancel the send nor let the recreated screen send it again. */
@RunWith(AndroidJUnit4::class)
class ComposeSendRotationTest {

    /** take() also unseals: leaving the cache sealed turns a later class's save() into a no-op. */
    @Before
    @After
    fun drainTheCache() {
        ComposeDraftCache.take()
        ComposeSend.resetForNewSession()
    }

    @Test
    fun aRecreatedComposeAdoptsTheSendInFlightAndShowsItsResult() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = Intent(context, ComposeActivity::class.java)
            .putExtra(ComposeActivity.EXTRA_TO, "recipient@example.com")
            .putExtra(ComposeActivity.EXTRA_SUBJECT, "Quarterly numbers")
        val release = CountDownLatch(1)
        val sends = AtomicInteger()

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            // What tapping Send starts: the relay call, outside any Activity scope.
            val inFlight = ComposeSend.start(
                CoroutineScope(Dispatchers.IO),
                MailDraft(to = "recipient@example.com", subject = "Quarterly numbers", body = "b"),
            ) { _, _ ->
                sends.incrementAndGet()
                release.await(10, TimeUnit.SECONDS)
                MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
            }

            scenario.recreate()
            scenario.onActivity { assertTrue("Send was offered again mid-send", it.isSendingForTest()) }

            release.countDown()
            runBlocking { inFlight.outcome.await() }

            // Success finishes the screen; the draft is not left behind to be sent twice. finish()
            // is asynchronous: system_server destroys the Activity after the idle sync returns.
            assertEquals(Lifecycle.State.DESTROYED, awaitDestroyed(scenario))
        }
        assertEquals(1, sends.get())
        assertNull(ComposeSend.current())
        assertNull(ComposeDraftCache.take())
    }

    private fun awaitDestroyed(scenario: ActivityScenario<ComposeActivity>): Lifecycle.State {
        val deadline = System.currentTimeMillis() + DESTROY_TIMEOUT_MS
        while (scenario.state != Lifecycle.State.DESTROYED && System.currentTimeMillis() < deadline) {
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            Thread.sleep(POLL_MS)
        }
        return scenario.state
    }

    private companion object {
        const val DESTROY_TIMEOUT_MS = 10_000L
        const val POLL_MS = 100L
    }
}
