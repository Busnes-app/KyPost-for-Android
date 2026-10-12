package org.kysecurity.mail.ui

import android.content.res.Configuration
import android.graphics.Rect
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.appcompat.view.ContextThemeWrapper
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R

/** Every message action must be fully on screen in a 320dp and a 360dp window, not clipped.
 *  Fixed-size buttons keep their width when they overflow, so this checks positions, not sizes. */
@RunWith(AndroidJUnit4::class)
class EmailDetailActionRowTest {

    @Test
    fun allEightActionsAreFullyVisibleAt320dp() = assertAllActionsVisibleAt(320)

    /** 360dp is the most common phone width and gets the larger size, so it is checked too. */
    @Test
    fun allEightActionsAreFullyVisibleAt360dp() = assertAllActionsVisibleAt(360)

    private fun assertAllActionsVisibleAt(widthDp: Int) {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        val base = instrumentation.targetContext
        val narrow = Configuration(base.resources.configuration).apply {
            screenWidthDp = widthDp
            smallestScreenWidthDp = widthDp
        }
        val context = ContextThemeWrapper(base.createConfigurationContext(narrow), R.style.Theme_KyPost)
        val density = context.resources.displayMetrics.density
        val clipped = mutableListOf<String>()
        instrumentation.runOnMainSync {
            val root = LayoutInflater.from(context).inflate(R.layout.activity_email_detail, null) as ViewGroup
            val width = (widthDp * density).toInt()
            val height = (640 * density).toInt()
            root.measure(
                View.MeasureSpec.makeMeasureSpec(width, View.MeasureSpec.EXACTLY),
                View.MeasureSpec.makeMeasureSpec(height, View.MeasureSpec.EXACTLY),
            )
            root.layout(0, 0, width, height)
            val content = root.getChildAt(0) as ViewGroup
            val visible = Rect(content.paddingLeft, 0, content.width - content.paddingRight, content.height)
            listOf(
                "reply" to R.id.actionReply, "replyAll" to R.id.actionReplyAll, "forward" to R.id.actionForward,
                "markUnread" to R.id.actionMarkUnread,
                "archive" to R.id.actionArchive, "move" to R.id.actionMove, "junk" to R.id.actionJunk,
                "delete" to R.id.actionDelete,
            ).forEach { (name, id) ->
                val button = root.findViewById<View>(id)
                val rect = Rect()
                button.getDrawingRect(rect)
                content.offsetDescendantRectToMyCoords(button, rect)
                if (rect.width() <= 0 || !visible.contains(rect)) clipped += "$name $rect outside $visible"
            }
        }
        assertEquals(emptyList<String>(), clipped)
    }
}
