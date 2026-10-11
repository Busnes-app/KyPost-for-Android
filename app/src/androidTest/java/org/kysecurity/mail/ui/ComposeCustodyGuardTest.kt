package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.R
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.pgp.PgpComposeState
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
    }

    @Test
    fun custodyResolvedWhileTheSubjectPromptIsOpenStopsTheSend() {
        val sends = AtomicInteger()
        val intent = Intent(instrumentation.targetContext, ComposeActivity::class.java)
            .putExtra(ComposeActivity.EXTRA_TO, "alice@example.com")
            .putExtra(ComposeActivity.EXTRA_BODY, "hello")
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { it.sendObserverForTest = { sends.incrementAndGet() } }
            awaitSubjectPrompt(scenario)

            scenario.onActivity {
                it.applyPgpComposeStateForTest(
                    PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true),
                )
            }
            onView(withText(R.string.compose_empty_subject_send)).inRoot(isDialog()).perform(click())
            instrumentation.waitForIdleSync()
            Thread.sleep(1_000) // the editor's HTML export answers on a later main-loop turn

            assertEquals("a webmail-only account reached the relay's plain send", 0, sends.get())
            scenario.onActivity { it.sendObserverForTest = null }
        }
    }

    /** Waits for the editor to report its body (until then Send asks for a message), taps Send
     *  once, then waits for the prompt to take focus. */
    private fun awaitSubjectPrompt(scenario: ActivityScenario<ComposeActivity>) {
        val deadline = System.currentTimeMillis() + 15_000
        var ready = false
        while (!ready && System.currentTimeMillis() < deadline) {
            scenario.onActivity { ready = it.bodyReportedForTest() }
            if (!ready) Thread.sleep(250)
        }
        check(ready) { "the editor never reported its body" }
        scenario.onActivity { it.sendForTest() }
        var last: Throwable? = null
        while (System.currentTimeMillis() < deadline + 5_000) {
            try {
                onView(withText(R.string.compose_empty_subject_title)).inRoot(isDialog()).check(matches(isDisplayed()))
                return
            } catch (e: Throwable) {
                last = e
                Thread.sleep(250)
            }
        }
        throw AssertionError("the empty-subject prompt never appeared", last)
    }
}
