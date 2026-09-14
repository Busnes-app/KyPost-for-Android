package org.kysecurity.mail.pgp

import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReadOutcomeDeliveryTest {
    private fun outcome(bytes: ByteArray) = ReadOutcome.Decrypted(
        DecryptedBody(
            html = null, plain = "body", protectedSubject = null,
            attachments = listOf(DecryptedAttachment("file", "application/octet-stream", bytes, null)),
        ),
        PgpSignatureState.UNSIGNED,
        "",
    )

    @Test
    fun cancelledDeliveryWipesACompletedResultBeforeTheConsumerCanAdoptIt() {
        val main = QueuedDispatcher()
        val worker = QueuedDispatcher()
        val bytes = byteArrayOf(1, 2, 3)
        var rendered = false
        val job = CoroutineScope(Job() + main).launch {
            deliverReadOutcome(worker, read = { outcome(bytes) }, render = { rendered = true; true })
        }
        main.runNext() // Suspend on the worker.
        worker.runNext() // Completed MIME result now waits for delivery on Main.
        assertArrayEquals(byteArrayOf(1, 2, 3), bytes)
        job.cancel() // Activity teardown before the queued Main continuation runs.
        main.runNext()

        assertTrue(job.isCompleted)
        assertFalse(rendered)
        assertArrayEquals(ByteArray(3), bytes)
    }

    @Test
    fun rejectedAndThrowingRenderersWipeButSuccessfulAdoptionKeepsBytes() = runBlocking {
        for (accepted in listOf(false, true)) {
            val bytes = byteArrayOf(1, 2, 3)
            deliverReadOutcome(Dispatchers.Unconfined, read = { outcome(bytes) }, render = { accepted })
            assertArrayEquals(if (accepted) byteArrayOf(1, 2, 3) else ByteArray(3), bytes)
        }
        val bytes = byteArrayOf(4, 5)
        val failure = runCatching {
            deliverReadOutcome(Dispatchers.Unconfined, read = { outcome(bytes) }, render = { error("render failed") })
        }.exceptionOrNull()
        assertTrue(failure is IllegalStateException)
        assertArrayEquals(ByteArray(2), bytes)
    }

    private class QueuedDispatcher : CoroutineDispatcher() {
        private val tasks = ArrayDeque<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) { tasks.add(block) }
        fun runNext() = tasks.removeFirst().run()
    }
}
