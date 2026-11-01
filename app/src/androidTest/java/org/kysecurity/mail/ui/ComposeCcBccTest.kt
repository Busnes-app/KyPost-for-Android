package org.kysecurity.mail.ui

import android.view.View
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.R

/** Cc and Bcc fold behind the To row's chevron, but never while either holds an address: a
 *  reply-all or a restored draft must show every recipient it is about to send to. */
@RunWith(AndroidJUnit4::class)
class ComposeCcBccTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext

    @Before
    fun clearDraft() {
        ComposeDraftCache.take()
    }

    @Test
    fun emptyCcAndBccStartFoldedAndTheChevronOpensThem() {
        ActivityScenario.launch<ComposeActivity>(ComposeActivity.internalIntent(context)).use { scenario ->
            scenario.onActivity { activity ->
                val chevron = activity.findViewById<View>(R.id.composeToInput).findViewById<View>(R.id.recipientInputExpandButton)
                assertEquals(View.VISIBLE, chevron.visibility)
                assertEquals(View.GONE, activity.findViewById<View>(R.id.composeCcInput).visibility)
                assertEquals(View.GONE, activity.findViewById<View>(R.id.composeBccInput).visibility)

                chevron.performClick()

                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.composeCcInput).visibility)
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.composeBccInput).visibility)
            }
        }
    }

    @Test
    fun aPrefilledBccIsShownAndCannotBeFoldedAway() {
        val intent = ComposeActivity.internalIntent(context)
            .putExtra(ComposeActivity.EXTRA_TO, "bob@example.com")
            .putExtra(ComposeActivity.EXTRA_BCC, "dan@example.com")
        ActivityScenario.launch<ComposeActivity>(intent).use { scenario ->
            scenario.onActivity { activity ->
                val chevron = activity.findViewById<View>(R.id.composeToInput).findViewById<View>(R.id.recipientInputExpandButton)
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.composeCcInput).visibility)
                assertEquals(View.VISIBLE, activity.findViewById<View>(R.id.composeBccInput).visibility)
                assertEquals(View.GONE, chevron.visibility)
            }
        }
    }
}
