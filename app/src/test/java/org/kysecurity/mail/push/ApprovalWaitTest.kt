package org.kysecurity.mail.push

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The approval wait belongs to the process, not one pairing screen; cancelling it from any
 *  screen, a newer link, an unpair or a session reset stops it and clears the card. */
class ApprovalWaitTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ui = PendingApprovalUi(approvalCode = "048213", serverHost = "mail.example.com")

    @Test
    fun cancelStopsTheWaitAndClearsTheCard() = runBlocking {
        val cancelled = CompletableDeferred<Unit>()
        ApprovalWait.start(ui, scope) {
            try {
                kotlinx.coroutines.awaitCancellation()
            } finally {
                cancelled.complete(Unit)
            }
        }
        assertEquals(ui, ApprovalWait.card.value)

        ApprovalWait.resetForNewSession()

        withTimeout(5_000) { cancelled.await() }
        assertNull(ApprovalWait.card.value)
    }

    @Test
    fun aFinishedWaitClearsItsCardButNotANewerOnes() = runBlocking {
        val release = CompletableDeferred<Unit>()
        val firstDone = CompletableDeferred<Unit>()
        ApprovalWait.start(ui, scope) { firstDone.complete(Unit) }
        withTimeout(5_000) { firstDone.await() }
        val newer = ui.copy(approvalCode = "111222")
        ApprovalWait.start(newer, scope) { release.await() }
        assertEquals(newer, ApprovalWait.card.value)
        assertTrue(release.complete(Unit))
        ApprovalWait.cancel()
        assertNull(ApprovalWait.card.value)
    }
}
