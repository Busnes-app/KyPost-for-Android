package org.kysecurity.mail.ui

import android.view.View
import android.view.ViewGroup
import androidx.core.widget.NestedScrollView
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeFalse
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeActivity
import org.kysecurity.mail.R

/**
 * Issue #114: on a closed foldable the keyboard left the body with no room, because the recipient
 * rows were fixed above it. Header and body now share one scroll container, so the header can
 * slide off the top. The wide layout puts them side by side and does not have the problem.
 */
@RunWith(AndroidJUnit4::class)
class ComposeKeyboardLayoutTest {

    @Test
    fun recipientRowsAndBodyScrollTogether() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        assumeFalse(context.resources.getBoolean(R.bool.nav_is_rail))

        ActivityScenario.launch(ComposeActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val toInput = activity.findViewById<View>(R.id.composeToInput)
                val body = activity.findViewById<View>(R.id.composeBodyEditor)
                val scroll = generateSequence(toInput.parent as? View) { it.parent as? View }
                    .firstOrNull { it is NestedScrollView }
                assertTrue("the recipient rows are not inside a scroll container", scroll != null)
                assertTrue("the body is not in the same scroll container as the recipient rows", isAncestor(scroll!!, body))
            }
        }
    }

    private fun isAncestor(ancestor: View, view: View): Boolean =
        generateSequence(view.parent as? ViewGroup) { it.parent as? ViewGroup }.any { it === ancestor }
}
