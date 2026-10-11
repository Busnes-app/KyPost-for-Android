package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

/** #131: how many refreshed rows landed above what the user was already looking at. */
class NewRowsAboveTest {

    private fun emails(vararg ids: String) =
        ids.map { Email(id = it, subject = "s$it", sender = "a@example.test", preview = "") }

    @Test
    fun countsOnlyRowsAboveTheOldFirstRow() {
        assertEquals(2, newRowsAbove(emails("c", "d"), emails("a", "b", "c", "d")))
    }

    @Test
    fun aRowInsertedBelowTheTopIsNotAnnounced() {
        assertEquals(0, newRowsAbove(emails("a", "c"), emails("a", "b", "c")))
    }

    @Test
    fun aFirstLoadAnnouncesNothing() {
        assertEquals(0, newRowsAbove(emails(), emails("a", "b")))
    }

    @Test
    fun aRemovedTopRowDoesNotCountSurvivorsAsNew() {
        assertEquals(1, newRowsAbove(emails("b", "c"), emails("a", "c")))
    }

    @Test
    fun anUnchangedListAnnouncesNothing() {
        assertEquals(0, newRowsAbove(emails("a", "b"), emails("a", "b")))
    }
}
