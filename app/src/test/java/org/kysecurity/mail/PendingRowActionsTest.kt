package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A held mail action is destructive: it must run exactly once, or not at all once undone. */
class PendingRowActionsTest {

    private fun email(id: String) = Email(id = id, subject = "", sender = "", preview = "", folder = "INBOX")

    @Test
    fun theTimerRunsTheActionOnce() {
        val actions = PendingRowActions()
        var runs = 0
        val entry = actions.hold(listOf(email("1"))) { runs++ }

        actions.commit(entry)
        actions.commit(entry)

        assertEquals(1, runs)
        assertTrue(actions.heldEmails().isEmpty())
    }

    @Test
    fun undoBeforeTheTimerMeansItNeverRuns() {
        val actions = PendingRowActions()
        var runs = 0
        val entry = actions.hold(listOf(email("1"))) { runs++ }

        assertTrue(actions.undo(entry))
        actions.commit(entry)
        actions.flush()

        assertEquals(0, runs)
    }

    @Test
    fun undoAfterTheActionRanIsRefused() {
        val actions = PendingRowActions()
        val entry = actions.hold(listOf(email("1"))) {}

        actions.commit(entry)

        assertFalse(actions.undo(entry))
    }

    @Test
    fun leavingTheScreenRunsEverythingHeldAndTheTimersThenDoNothing() {
        val actions = PendingRowActions()
        val ran = mutableListOf<String>()
        val first = actions.hold(listOf(email("1"))) { ran += "1" }
        val second = actions.hold(listOf(email("2"), email("3"))) { ran += "2+3" }
        assertEquals(listOf("1", "2", "3"), actions.heldEmails().map { it.id })

        actions.flush()
        actions.commit(first)
        actions.commit(second)

        assertEquals(listOf("1", "2+3"), ran)
        assertFalse(actions.undo(second))
    }
}
