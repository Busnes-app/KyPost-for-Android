package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import okhttp3.Call
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposePgpController
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.push.PairingData
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger

/** Every way to Send obeys the account's custody, including a confirmation answered after
 *  custody turned out to be webmail-only. */
@RunWith(AndroidJUnit4::class)
class ComposeCustodyGuardTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Before
    @After
    fun reset() {
        ComposeDraftCache.take()
        MailRuntime.invalidate()
        ComposeActivity.pgpControllerForTest = null
        ComposePgpController.resetSessionCache()
    }

    @Test
    fun failedBootstrapKeepsCustodyUnknownAndSendBlocked() {
        val bootstrapCalls = AtomicInteger()
        val offline = Call.Factory { bootstrapCalls.incrementAndGet(); throw IOException("offline") }
        ComposeActivity.pgpControllerForTest = ComposePgpController(
            pairingProvider = {
                PairingData(
                    subscriberId = "sub-1", serverUrl = "https://relay.example.com", registrationUrl = "",
                    pairingToken = "", deviceId = "d", deviceSecret = "s", pairedAtEpochMs = 0L,
                )
            },
            bootstrapClient = PgpBootstrapClient(callFactory = offline),
            recipientKeyClient = RecipientKeyClient(callFactory = offline),
        )
        val sends = AtomicInteger()
        val intent = ComposeActivity.internalIntent(instrumentation.targetContext)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_SUBJECT, "hi")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            waitUntil(scenario) { it.custodySettledForTest() && it.sendEnabledForTest() != null }
            assertTrue("bootstrap was never attempted", bootstrapCalls.get() > 0)

            scenario.onActivity {
                assertEquals("Send enabled after a failed bootstrap", false, it.sendEnabledForTest())
                it.sendObserverForTest = { sends.incrementAndGet() }
                it.bodyEmptyForTest = false
                it.sendForTest()
                it.confirmSendWithoutSubjectForTest()
            }
            instrumentation.waitForIdleSync()

            assertEquals("sent without knowing the account's custody", 0, sends.get())
            scenario.onActivity { it.sendObserverForTest = null }
        }
    }

    private fun waitUntil(scenario: ActivityScenario<ComposeActivity>, condition: (ComposeActivity) -> Boolean) {
        val deadline = System.currentTimeMillis() + 10_000
        while (System.currentTimeMillis() < deadline) {
            var met = false
            scenario.onActivity { met = condition(it) }
            if (met) return
            Thread.sleep(50)
        }
        throw AssertionError("condition not met within 10 s")
    }

    @Test
    fun custodyResolvedWhileTheSubjectPromptIsOpenStopsTheSend() {
        val sends = AtomicInteger()
        // internalIntent: only an in-app launch may prefill recipients (ComposeIntentParser).
        val intent = ComposeActivity.internalIntent(instrumentation.targetContext)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity {
                it.sendObserverForTest = { sends.incrementAndGet() }
                // The editor's own report comes from its page, which CI emulators never finish.
                it.bodyEmptyForTest = false
                // Custody resolves to webmail-only after the prompt was raised...
                it.applyPgpComposeStateForTest(
                    PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
                )
                // ...and then the prompt's Send runs its callback.
                it.confirmSendWithoutSubjectForTest()
            }
            instrumentation.waitForIdleSync()

            assertEquals("a webmail-only account went on to send", 0, sends.get())
            scenario.onActivity { it.sendObserverForTest = null }
        }
    }
}
