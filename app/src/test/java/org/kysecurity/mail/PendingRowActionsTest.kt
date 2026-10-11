package org.kysecurity.mail

import com.google.android.material.snackbar.BaseTransientBottomBar.BaseCallback
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A held mail action is destructive: it must run exactly once, or not at all once undone. */
class PendingRowActionsTest {

    private fun email(id: String) = Email(id = id, subject = "", sender = "", preview = "", folder = "INBOX")

    @Test
    fun undoTakesBackEveryHeldActionAndNoneRunsLater() {
        val actions = PendingRowActions()
        val ran = mutableListOf<String>()
        actions.hold(listOf(email("1"))) { ran += "1" }
        actions.hold(listOf(email("2"))) { ran += "2" }

        assertTrue(actions.undoAll())
        actions.flush()

        assertEquals(emptyList<String>(), ran)
        assertTrue(actions.heldEmails().isEmpty())
    }

    @Test
    fun flushRunsEachHeldActionOnce() {
        val actions = PendingRowActions()
        val ran = mutableListOf<String>()
        actions.hold(listOf(email("1"))) { ran += "1" }
        actions.hold(listOf(email("2"), email("3"))) { ran += "2+3" }
        assertEquals(listOf("1", "2", "3"), actions.heldEmails().map { it.id })
        assertEquals(2, actions.heldCount())

        actions.flush()
        actions.flush()

        assertEquals(listOf("1", "2+3"), ran)
        assertFalse("nothing is left to undo once sent", actions.undoAll())
    }

    /** The bar's own timeout follows the accessibility "time to take action" setting. */
    @Test
    fun onlyATimedOutOrSwipedAwayBarCommits() {
        assertTrue(commitsOnDismiss(BaseCallback.DISMISS_EVENT_TIMEOUT))
        assertTrue(commitsOnDismiss(BaseCallback.DISMISS_EVENT_SWIPE))
        assertFalse(commitsOnDismiss(BaseCallback.DISMISS_EVENT_ACTION))
        assertFalse(commitsOnDismiss(BaseCallback.DISMISS_EVENT_CONSECUTIVE))
        assertFalse(commitsOnDismiss(BaseCallback.DISMISS_EVENT_MANUAL))
    }
}
