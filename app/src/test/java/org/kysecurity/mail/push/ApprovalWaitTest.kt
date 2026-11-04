package org.kysecurity.mail.push

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The approval wait belongs to the process, not one pairing screen; cancelling it from any
 *  screen, a newer link, an unpair or a session reset stops it and clears the card. */
class ApprovalWaitTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ui = PendingApprovalUi(approvalCode = "048213", serverHost = "mail.example.com")

    @Test
    fun cancelStopsTheWaitAndClearsTheCard() = runBlocking {
        val cancelled = CompletableDeferred<Unit>()
        val started = CompletableDeferred<Unit>()
        ApprovalWait.start(ui, scope) {
            started.complete(Unit)
            try {
                kotlinx.coroutines.awaitCancellation()
            } finally {
                cancelled.complete(Unit)
            }
        }
        assertEquals(ui, ApprovalWait.card.value)
        // Cancelled before it starts, the body never runs and its finally would never fire.
        withTimeout(5_000) { started.await() }

        ApprovalWait.resetForNewSession()

        withTimeout(5_000) { cancelled.await() }
        assertNull(ApprovalWait.card.value)
    }

    @Test
    fun aFinishedWaitClearsItsCard() = runBlocking {
        val done = CompletableDeferred<Unit>()
        ApprovalWait.start(ui, scope) { done.complete(Unit) }
        withTimeout(5_000) {
            done.await()
            while (ApprovalWait.card.value != null) kotlinx.coroutines.delay(10)
        }
        assertNull(ApprovalWait.card.value)
    }
}
