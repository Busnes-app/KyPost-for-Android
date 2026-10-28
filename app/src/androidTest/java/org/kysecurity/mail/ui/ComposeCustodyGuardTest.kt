package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.IOException
import java.util.concurrent.atomic.AtomicInteger
import okhttp3.Call
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ComposePgpController
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.afterSplash

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
        ActivityScenario.launch<ComposeActivity>(intent).afterSplash().use { scenario ->
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

    /** Taps the real prompt. Custody is known (no PGP identity) when the prompt is raised, then
     *  turns webmail-only before Send is tapped: the tap must not reach the relay. */
    @Test
    fun custodyResolvedWhileTheSubjectPromptIsOpenStopsTheSend() {
        val sends = AtomicInteger()
        // internalIntent: only an in-app launch may prefill recipients (ComposeIntentParser).
        val intent = ComposeActivity.internalIntent(instrumentation.targetContext)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).afterSplash().use { scenario ->
            scenario.onActivity {
                it.sendObserverForTest = { sends.incrementAndGet() }
                // The editor's own report comes from its page, which CI emulators never finish.
                it.bodyEmptyForTest = false
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false))
                it.sendForTest()
            }
            onView(withText(R.string.compose_empty_subject_title)).inRoot(isDialog()).check(matches(isDisplayed()))

            scenario.onActivity {
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true))
            }
            onView(withText(R.string.compose_empty_subject_send)).inRoot(isDialog()).perform(click())
            instrumentation.waitForIdleSync()

            assertEquals("a webmail-only account went on to send", 0, sends.get())
            scenario.onActivity { it.sendObserverForTest = null }
        }
    }

    /** Scheduling encrypts the copy for Drafts on this device, so only an account whose key is here
     *  is offered it: never one whose key the server holds, nor one still being looked up. */
    @Test
    fun scheduleAndSaveDraftAreOfferedOnlyWhereThisDeviceHoldsTheKey() {
        ActivityScenario.launch<ComposeActivity>(ComposeActivity.internalIntent(instrumentation.targetContext)).afterSplash().use { scenario ->
            scenario.onActivity { assertFalse("offered before custody is known", it.scheduleOfferedForTest()) }
            scenario.onActivity {
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false))
                assertFalse("offered to a server-key account", it.scheduleOfferedForTest())
                assertFalse("Save draft offered to a server-key account", it.saveDraftOfferedForTest())
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true))
                assertFalse("offered to a webmail-only account", it.scheduleOfferedForTest())
                it.applyPgpComposeStateForTest(PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false, clientSide = true))
                assertTrue("not offered where the key is on this device", it.scheduleOfferedForTest())
                assertTrue("Save draft not offered where the key is on this device", it.saveDraftOfferedForTest())
            }
        }
    }
}
