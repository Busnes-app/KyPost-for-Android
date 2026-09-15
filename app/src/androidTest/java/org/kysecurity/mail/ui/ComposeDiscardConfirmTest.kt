package org.kysecurity.mail.ui

import android.content.Intent
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withId
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.R

/** Issue #113: back used to finish the composer and, with it, silently drop whatever was typed. */
@RunWith(AndroidJUnit4::class)
class ComposeDiscardConfirmTest {

    @After
    fun drainTheCache() {
        ComposeDraftCache.take()
    }

    @Test
    fun backWithTypedMailAsksFirst_andKeepEditingStays() {
        ActivityScenario.launch<ComposeActivity>(composeIntent().putExtra(ComposeActivity.EXTRA_BODY, BODY)).use { scenario ->
            awaitMirroredBody(scenario)
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            awaitDialog()
            onView(withText(R.string.compose_discard_keep)).inRoot(isDialog()).perform(click())

            scenario.onActivity { assertFalse("keep editing must not finish the composer", it.isFinishing) }
            onView(withId(R.id.composeSubjectField)).check(matches(isDisplayed()))
        }
    }

    @Test
    fun discardFinishesTheComposer() {
        ActivityScenario.launch<ComposeActivity>(composeIntent().putExtra(ComposeActivity.EXTRA_SUBJECT, "Quarterly numbers")).use { scenario ->
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            awaitDialog()
            onView(withText(R.string.compose_discard_confirm)).inRoot(isDialog()).perform(click())

            awaitState(scenario, Lifecycle.State.DESTROYED)
        }
    }

    @Test
    fun backOnAnUntouchedComposerJustLeaves() {
        ActivityScenario.launch<ComposeActivity>(composeIntent()).use { scenario ->
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            awaitState(scenario, Lifecycle.State.DESTROYED)
        }
    }

    private fun composeIntent(): Intent =
        Intent(InstrumentationRegistry.getInstrumentation().targetContext, ComposeActivity::class.java)

    /** The prompt waits on the editor's async HTML export, so it is not up the instant back lands. */
    private fun awaitDialog() {
        var last: Throwable? = null
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            try {
                onView(withText(R.string.compose_discard_title)).inRoot(isDialog()).check(matches(isDisplayed()))
                return
            } catch (e: Throwable) {
                last = e
                Thread.sleep(POLL_INTERVAL_MS)
            }
        }
        throw AssertionError("the discard prompt never appeared", last)
    }

    private fun awaitState(scenario: ActivityScenario<ComposeActivity>, state: Lifecycle.State) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline && scenario.state != state) Thread.sleep(POLL_INTERVAL_MS)
        assertEquals(state, scenario.state)
    }

    private fun awaitMirroredBody(scenario: ActivityScenario<ComposeActivity>) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val mirrored = arrayOfNulls<String>(1)
            scenario.onActivity { mirrored[0] = it.mirroredBodyHtmlForTest() }
            if (mirrored[0].orEmpty().contains(BODY)) return
            Thread.sleep(POLL_INTERVAL_MS)
        }
        throw AssertionError("the editor never mirrored its body within ${TIMEOUT_MS}ms")
    }

    private companion object {
        const val BODY = "account balance is 4212"
        const val TIMEOUT_MS = 20_000L
        const val POLL_INTERVAL_MS = 250L
    }
}
