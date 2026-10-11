package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Test

/** kypost-server refuses more than 500 changes (413) or a body over 1 MiB (400) per push. */
class ContactPushBatchesTest {

    @Test
    fun countCap_splitsAt500() {
        val batches = pushBatches((1..1200).toList()) { 10 }

        assertEquals(listOf(500, 500, 200), batches.map { it.size })
        assertEquals((1..1200).toList(), batches.flatten())
    }

    @Test
    fun byteCap_splitsBeforeTheBudgetIsExceeded() {
        val batches = pushBatches((1..10).toList()) { MAX_PUSH_BYTES / 4 }

        assertEquals(listOf(4, 4, 2), batches.map { it.size })
    }

    @Test
    fun anOversizedChange_travelsAlone() {
        val batches = pushBatches(listOf(1, 2, 3)) { if (it == 2) MAX_PUSH_BYTES * 2 else 1 }

        assertEquals(listOf(listOf(1), listOf(2), listOf(3)), batches)
    }

    @Test
    fun nothingQueued_noBatches() {
        assertEquals(emptyList<List<Int>>(), pushBatches(emptyList<Int>()) { 1 })
    }
}
