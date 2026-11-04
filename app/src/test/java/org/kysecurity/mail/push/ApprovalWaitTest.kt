package org.kysecurity.mail.push

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

/** The approval wait belongs to the process, not one pairing screen; cancelling it from any
 *  screen, a newer link, an unpair or a session reset stops it and clears the card. */
class ApprovalWaitTest {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val ui = PendingApprovalUi(approvalCode = "048213", serverHost = "mail.example.com")
    private val denied = NativeRegistrationResult.Error("This pairing was denied or has expired", notApproved = true)

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
        ApprovalWait.start(ui, scope) { done.complete(Unit); denied }
        withTimeout(5_000) {
            done.await()
            while (ApprovalWait.card.value != null) kotlinx.coroutines.delay(10)
        }
        assertNull(ApprovalWait.card.value)
        assertSame(denied, ApprovalWait.takeResult())
    }

    /** The screen that started the wait is usually gone by the time it ends (the app lock finished
     *  it), so the outcome is held for whichever pairing screen is current, once. */
    @Test
    fun aFinishedWaitHoldsItsOutcomeForOneScreen() = runBlocking {
        ApprovalWait.start(ui, scope) { denied }
        withTimeout(5_000) { ApprovalWait.result.first { it != null } }

        assertSame(denied, ApprovalWait.takeResult())
        assertNull(ApprovalWait.takeResult())
        assertNull(ApprovalWait.result.value)
    }

    @Test
    fun aSessionResetDropsAnOutcomeNobodyTook() = runBlocking {
        ApprovalWait.start(ui, scope) { denied }
        withTimeout(5_000) { ApprovalWait.result.first { it != null } }

        ApprovalWait.resetForNewSession()

        assertNull(ApprovalWait.takeResult())
    }

    /** An approved replacement purges the old account inside the wait, through the real session
     *  reset. That reset must not cancel the wait finishing the pairing: its result still lands. */
    @Test
    fun theResetAWaitRunsItselfDoesNotCancelIt() = runBlocking {
        val paired = NativeRegistrationResult.Success(syncedAtEpochMs = 1L, deviceId = "d", deviceSecret = null)
        ApprovalWait.start(ui, scope) {
            kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable + Dispatchers.Default) {
                org.kysecurity.mail.ProcessState.resetAll()
            }
            paired
        }
        withTimeout(5_000) { ApprovalWait.result.first { it != null } }

        assertSame(paired, ApprovalWait.takeResult())
        assertNull(ApprovalWait.card.value)
    }

    @Test
    fun aCancelledWaitReportsNothing() = runBlocking {
        val started = CompletableDeferred<Unit>()
        ApprovalWait.start(ui, scope) {
            started.complete(Unit)
            try {
                kotlinx.coroutines.awaitCancellation()
            } finally {
                // As the coordinator's finally: still running after the cancel returns.
                kotlinx.coroutines.withContext(kotlinx.coroutines.NonCancellable) { kotlinx.coroutines.delay(50) }
            }
        }
        withTimeout(5_000) { started.await() }

        ApprovalWait.cancel()
        kotlinx.coroutines.delay(200)

        assertNull(ApprovalWait.result.value)
    }
}
