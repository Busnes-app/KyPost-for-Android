package org.kysecurity.mail.ui

import android.view.LayoutInflater
import android.view.View
import androidx.appcompat.view.ContextThemeWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R

/** Seven 44dp actions do not fit a 320dp window; none may be squeezed out of reach. */
@RunWith(AndroidJUnit4::class)
class EmailDetailActionRowTest {

    @Test
    fun everyActionKeepsItsFullSizeAt320dp() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val context = ContextThemeWrapper(instrumentation.targetContext, R.style.Theme_KyPost)
        val density = context.resources.displayMetrics.density
        val widths = mutableMapOf<String, Int>()
        instrumentation.runOnMainSync {
            val root = LayoutInflater.from(context).inflate(R.layout.activity_email_detail, null)
            root.measure(
                View.MeasureSpec.makeMeasureSpec((320 * density).toInt(), View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec((640 * density).toInt(), View.MeasureSpec.EXACTLY),
            )
            listOf(
                "reply" to R.id.actionReply, "replyAll" to R.id.actionReplyAll, "forward" to R.id.actionForward,
                "archive" to R.id.actionArchive, "move" to R.id.actionMove, "junk" to R.id.actionJunk,
                "delete" to R.id.actionDelete,
            ).forEach { (name, id) -> widths[name] = root.findViewById<View>(id).measuredWidth }
        }
        val full = (44 * density).toInt()
        assertEquals(widths.mapValues { full }, widths)
    }
}
