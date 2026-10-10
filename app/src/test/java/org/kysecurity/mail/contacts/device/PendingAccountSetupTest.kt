package org.kysecurity.mail.contacts.device

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/** Every add-account request gets exactly one answer, so no caller is left waiting. */
class PendingAccountSetupTest {
    private val answers = mutableListOf<String>()

    private fun hold(tag: String) = PendingAccountSetup.hold(
        onAdded = { answers += "$tag added $it" },
        onCancelled = { answers += "$tag cancelled" },
    )

    @AfterTest
    fun clear() = PendingAccountSetup.cancel()

    @Test
    fun completingAnswersOnce() {
        hold("a")
        PendingAccountSetup.complete("KyPost")
        PendingAccountSetup.complete("KyPost")
        PendingAccountSetup.cancel()

        assertEquals(listOf("a added KyPost"), answers)
        assertFalse(PendingAccountSetup.isPending)
    }

    @Test
    fun aNewRequestCancelsTheOldOne() {
        hold("a")
        hold("b")
        PendingAccountSetup.complete("KyPost")

        assertEquals(listOf("a cancelled", "b added KyPost"), answers)
    }

    /** Two requests arriving together: both are answered, one displaced and one completed. */
    @Test
    fun concurrentHolds_neitherRequestIsLost() {
        val answered = java.util.concurrent.atomic.AtomicInteger()
        repeat(2_000) {
            val gate = java.util.concurrent.CyclicBarrier(2)
            val threads = List(2) {
                kotlin.concurrent.thread {
                    gate.await()
                    PendingAccountSetup.hold(onAdded = { answered.incrementAndGet() }, onCancelled = { answered.incrementAndGet() })
                }
            }
            threads.forEach { it.join(5_000) }
            PendingAccountSetup.cancel()
        }

        assertEquals(4_000, answered.get())
    }

    @Test
    fun aSessionResetCancels() {
        hold("a")
        PendingAccountSetup.resetForNewSession()

        assertEquals(listOf("a cancelled"), answers)
    }
}
