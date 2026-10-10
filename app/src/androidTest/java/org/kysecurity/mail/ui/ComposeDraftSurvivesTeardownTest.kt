package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache

/**
 * The editor exports its HTML asynchronously. A configuration change destroys the Activity before
 * that callback can land — and the replacement reads [ComposeDraftCache] in `onCreate`, so a draft
 * that arrives afterwards is already too late. `onStop` has to save what it already holds.
 */
@RunWith(AndroidJUnit4::class)
class ComposeDraftSurvivesTeardownTest {

    /** take() also unseals: leaving the cache sealed turns a later class's save() into a no-op. */
    @After
    fun drainTheCache() {
        ComposeDraftCache.take()
    }

    @Test
    fun aDestroyThatOutrunsTheEditorExportStillLeavesTheDraft() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "recipient@example.com")
            .putExtra(ComposeActivity.EXTRA_SUBJECT, "Quarterly numbers")
            .putExtra(ComposeActivity.EXTRA_BODY, BODY)

        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            awaitMirroredBody(scenario)

            // Destroy and recreate: onStop, then onDestroy, with no main-loop turn in between for
            // the export callback to use. The replacement takes the cache in onCreate.
            scenario.recreate()

            scenario.onActivity { activity ->
                val restored = activity.restoredDraftForTest
                assertTrue("the draft was dropped by the teardown", restored != null)
                assertTrue(
                    "the draft came back without its body: ${restored?.bodyHtml}",
                    restored!!.bodyHtml.contains(BODY),
                )
                assertTrue(restored.to.contains("recipient@example.com"))
                assertTrue(restored.subject == "Quarterly numbers")
            }
        }
    }

    /** The WebView has to load its editor document before it can export anything. */
    private fun awaitMirroredBody(scenario: ActivityScenario<ComposeActivity>) {
        val deadline = System.currentTimeMillis() + MIRROR_TIMEOUT_MS
        while (System.currentTimeMillis() < deadline) {
            val mirrored = arrayOfNulls<String>(1)
            scenario.onActivity { mirrored[0] = it.mirroredBodyHtmlForTest() }
            if (mirrored[0].orEmpty().contains(BODY)) return
            Thread.sleep(POLL_INTERVAL_MS)
        }
        throw AssertionError("the editor never mirrored its body within ${MIRROR_TIMEOUT_MS}ms")
    }

    private companion object {
        const val BODY = "account balance is 4212"
        const val MIRROR_TIMEOUT_MS = 20_000L
        const val POLL_INTERVAL_MS = 250L
    }
}
