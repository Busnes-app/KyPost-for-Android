package org.kysecurity.mail.ui

import android.content.Intent
import androidx.annotation.StringRes
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

    /** No wait for the editor: back lands before its first export, and the mirror must decide. */
    @Test
    fun backWithTypedMailAsksFirst_andKeepEditingStays() {
        ActivityScenario.launch<ComposeActivity>(composeIntent().putExtra(ComposeActivity.EXTRA_BODY, BODY)).use { scenario ->
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            awaitDialog()
            tapPromptButton(scenario, R.string.compose_discard_keep)

            scenario.onActivity { assertFalse("keep editing must not finish the composer", it.isFinishing) }
            onView(withId(R.id.composeSubjectField)).check(matches(isDisplayed()))
        }
    }

    @Test
    fun discardFinishesTheComposer() {
        ActivityScenario.launch<ComposeActivity>(composeIntent().putExtra(ComposeActivity.EXTRA_SUBJECT, "Quarterly numbers")).use { scenario ->
            scenario.onActivity { it.onBackPressedDispatcher.onBackPressed() }

            awaitDialog()
            tapPromptButton(scenario, R.string.compose_discard_confirm)

            awaitState(scenario, Lifecycle.State.DESTROYED)
        }
    }

    /** Two presses inside the export window must raise one prompt, and Discard must still work. */
    @Test
    fun aDoubleBackPressRaisesOnePromptAndDiscardStillFinishes() {
        ActivityScenario.launch<ComposeActivity>(composeIntent().putExtra(ComposeActivity.EXTRA_BODY, BODY)).use { scenario ->
            scenario.onActivity {
                it.onBackPressedDispatcher.onBackPressed()
                it.onBackPressedDispatcher.onBackPressed()
            }

            awaitDialog()
            scenario.onActivity { assertEquals(1, it.discardPromptCountForTest()) }
            tapPromptButton(scenario, R.string.compose_discard_confirm)

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
        ComposeActivity.internalIntent(InstrumentationRegistry.getInstrumentation().targetContext)

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

    /** One UI drops a touch on a window that is still fading in (logcat: "Not sending motion to …
     *  window opacity=0.40 is below the threshold"), and Espresso taps the moment the prompt is
     *  up — so on a Galaxy the first tap can land mid-animation and go nowhere. Tap until the
     *  prompt is gone: the composer has its window focus back, or Discard has started finishing it. */
    private fun tapPromptButton(scenario: ActivityScenario<ComposeActivity>, @StringRes label: Int) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (true) {
            onView(withText(label)).inRoot(isDialog()).perform(click())
            val settled = System.currentTimeMillis() + TAP_SETTLE_MS
            while (System.currentTimeMillis() < settled) {
                if (scenario.state != Lifecycle.State.RESUMED) return
                var focused = false
                scenario.onActivity { focused = it.hasWindowFocus() }
                if (focused) return
                Thread.sleep(POLL_INTERVAL_MS)
            }
            if (System.currentTimeMillis() >= deadline) throw AssertionError("the discard prompt ignored every tap")
        }
    }

    private fun awaitState(scenario: ActivityScenario<ComposeActivity>, state: Lifecycle.State) {
        val deadline = System.currentTimeMillis() + TIMEOUT_MS
        while (System.currentTimeMillis() < deadline && scenario.state != state) Thread.sleep(POLL_INTERVAL_MS)
        assertEquals(state, scenario.state)
    }

    private companion object {
        const val BODY = "account balance is 4212"
        const val TIMEOUT_MS = 20_000L
        const val POLL_INTERVAL_MS = 250L
        const val TAP_SETTLE_MS = 2_000L
    }
}
