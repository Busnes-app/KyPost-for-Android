package org.kysecurity.mail.ui

import android.content.Intent
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onIdle
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.doesNotExist
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withSubstring
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.ScheduledActivity
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.ScheduledSend
import java.time.Instant
import org.kysecurity.mail.afterSplash

/** The scheduled list against a relay the test controls: only a waiting send can be canceled, and
 *  only after the user confirms. */
@RunWith(AndroidJUnit4::class)
class ScheduledActivityTest {

    private val source = FakeMailSource()
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val at = Instant.parse("2026-10-20T08:00:00Z")

    @Before
    fun installRelay() {
        MailRuntime.invalidate()
        MailRuntime.sourceForTest = source
        source.scheduled = {
            MailOutcome.Success(
                listOf(
                    ScheduledSend("s1", "scheduled", "", at, "Waiting one", listOf("a@example.invalid")),
                    ScheduledSend("s2", "sending", "", at, "Leaving now", listOf("b@example.invalid")),
                ),
            )
        }
    }

    @After
    fun releaseRelay() {
        MailRuntime.sourceForTest = null
        MailRuntime.invalidate()
    }

    private fun launch() = ActivityScenario.launch<ScheduledActivity>(Intent(context, ScheduledActivity::class.java)).afterSplash()

    @Test
    fun aWaitingSendIsCanceledOnlyAfterConfirming() {
        launch().use {
            eventually { onView(withSubstring("Waiting one")).perform(click()) }
            onView(withText(R.string.scheduled_cancel_title)).inRoot(isDialog()).check(matches(isDisplayed()))
            assertEquals(emptyList<String>(), source.cancels.toList())

            onView(withId(android.R.id.button1)).perform(click())

            eventually { assertEquals(listOf("s1"), source.cancels.toList()) }
        }
    }

    @Test
    fun aSendAlreadyLeavingCannotBeCanceled() {
        launch().use {
            eventually { onView(withSubstring("Leaving now")).perform(click()) }
            onIdle()
            onView(withText(R.string.scheduled_cancel_title)).check(doesNotExist())
            assertTrue(source.cancels.isEmpty())
        }
    }

    /** The list loads on a worker Espresso does not watch. */
    private fun eventually(check: () -> Unit) {
        val deadline = System.nanoTime() + 10_000_000_000L
        while (true) {
            try {
                return check()
            } catch (e: Throwable) {
                if (System.nanoTime() > deadline) throw e
                Thread.sleep(50)
            }
        }
    }
}
