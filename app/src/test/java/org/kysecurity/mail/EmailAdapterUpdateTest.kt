package org.kysecurity.mail

import androidx.recyclerview.widget.ListUpdateCallback
import org.junit.Assert.assertEquals
import org.junit.Test

/** Granular updates only: notifyDataSetChanged() breaks in-flight ItemTouchHelper swipes. */
class EmailAdapterUpdateTest {

    private fun email(id: String, subject: String = "subject $id") =
        Email(id = id, subject = subject, sender = "sender@example.test", preview = "preview")

    private class RecordingUpdates : ListUpdateCallback {
        val ops = mutableListOf<String>()
        override fun onInserted(position: Int, count: Int) { ops += "insert($position,$count)" }
        override fun onRemoved(position: Int, count: Int) { ops += "remove($position,$count)" }
        override fun onMoved(fromPosition: Int, toPosition: Int) { ops += "move($fromPosition,$toPosition)" }
        override fun onChanged(position: Int, count: Int, payload: Any?) { ops += "change($position,$count)" }
    }

    private fun updates(old: List<Email>, new: List<Email>, dayChanged: Boolean = false): List<String> =
        RecordingUpdates().also { dispatchEmailListUpdate(old, new, it, dayChanged) }.ops

    /** Past midnight, yesterday's "9:05 AM" must become a date even when no mail changed. */
    @Test
    fun anUnchangedListIsRebound_whenTheDayChanges() {
        val rows = listOf(email("a"), email("b"))
        assertEquals(emptyList<String>(), updates(rows, rows))
        assertEquals(listOf("change(0,2)"), updates(rows, rows, dayChanged = true))
    }

    @Test
    fun swipingOneEmailAwayRemovesOnlyThatRow() {
        val before = listOf(email("a"), email("b"), email("c"))
        val after = listOf(email("a"), email("c"))

        assertEquals(listOf("remove(1,1)"), updates(before, after))
    }

    @Test
    fun swipingTwoEmailsAwayInSuccessionStaysGranular() {
        val start = listOf(email("a"), email("b"), email("c"))
        val afterFirst = listOf(email("b"), email("c"))
        val afterSecond = listOf(email("c"))

        assertEquals(listOf("remove(0,1)"), updates(start, afterFirst))
        assertEquals(listOf("remove(0,1)"), updates(afterFirst, afterSecond))
    }

    @Test
    fun unchangedListReportsNothing() {
        val emails = listOf(email("a"), email("b"))

        assertEquals(emptyList<String>(), updates(emails, emails))
    }

    @Test
    fun editedRowReportsOnlyThatRow() {
        val before = listOf(email("a"), email("b"))
        val after = listOf(email("a"), email("b", subject = "read now"))

        assertEquals(listOf("change(1,1)"), updates(before, after))
    }

    @Test
    fun newMailArrivingReportsAnInsert() {
        val before = listOf(email("b"))
        val after = listOf(email("a"), email("b"))

        assertEquals(listOf("insert(0,1)"), updates(before, after))
    }
}
