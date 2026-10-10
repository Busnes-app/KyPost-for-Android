package org.kysecurity.mail

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.Request
import okhttp3.Response
import okio.Timeout
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.mail.OutgoingAttachment
import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** A session reset must stop a send it overlaps; without one, the send carries on to be adopted. */
class ComposeSendTest {

    @After
    fun reset() = ComposeSend.resetForNewSession()

    /** Blocks in [execute] until cancelled, like a request waiting on a slow relay. */
    private class BlockingCall : Call {
        private val cancelled = CountDownLatch(1)
        override fun request(): Request = Request.Builder().url("https://relay.example.test/api/mail/send").build()
        override fun execute(): Response {
            cancelled.await(30, TimeUnit.SECONDS)
            throw IOException("Canceled")
        }
        override fun enqueue(responseCallback: Callback) = throw UnsupportedOperationException()
        override fun cancel() = cancelled.countDown()
        override fun isExecuted(): Boolean = true
        override fun isCanceled(): Boolean = cancelled.count == 0L
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = BlockingCall()
    }

    private fun draft(bytes: ByteArray) = MailDraft(
        to = "recipient@example.test",
        subject = "Subject",
        body = "Body",
        attachments = listOf(OutgoingAttachment("a.bin", "application/octet-stream", bytes)),
    )

    @Test
    fun aSessionResetStopsTheSendInFlightAndZeroesItsAttachments() {
        val call = BlockingCall()
        val entered = CountDownLatch(1)
        val finished = CountDownLatch(1)
        val bytes = byteArrayOf(1, 2, 3)
        val sending = ComposeSend.start(CoroutineScope(Dispatchers.IO), draft(bytes), ProcessState.generation()) { _, onCall ->
            try {
                onCall(call)
                entered.countDown()
                call.execute()
                MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
            } catch (e: IOException) {
                MailOutcome.UpstreamFailure("canceled")
            } finally {
                finished.countDown()
            }
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))

        ComposeSend.resetForNewSession()

        assertTrue(call.isCanceled())
        assertEquals("reset returned while the send was still running", 0L, finished.count)
        assertTrue(sending.outcome.isCancelled)
        assertArrayEquals(ByteArray(3), bytes)
        assertNull(ComposeSend.current())
    }

    @Test
    fun aSendQueuedBeforeTheResetNeverRuns() {
        val executor = Executors.newSingleThreadExecutor()
        val gate = CountDownLatch(1)
        executor.execute { gate.await(5, TimeUnit.SECONDS) }
        val ran = AtomicInteger()
        try {
            ComposeSend.start(CoroutineScope(executor.asCoroutineDispatcher()), draft(byteArrayOf(1)), ProcessState.generation()) { _, _ ->
                ran.incrementAndGet()
                MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
            }

            ComposeSend.resetForNewSession()
            gate.countDown()
            executor.submit {}.get(5, TimeUnit.SECONDS)

            assertEquals(0, ran.get())
        } finally {
            executor.shutdownNow()
        }
    }

    /** The composer captured its session, then the session ended before its async export landed. */
    @Test
    fun aSubmissionFromAnEndedSessionIsRefusedAndZeroed() {
        val session = ProcessState.generation()
        ProcessState.resetAll()
        val bytes = byteArrayOf(1, 2, 3)
        val transportCalls = AtomicInteger()

        val sending = ComposeSend.start(CoroutineScope(Dispatchers.IO), draft(bytes), session) { _, _ ->
            transportCalls.incrementAndGet()
            MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
        }

        assertTrue(sending.outcome.isCancelled)
        assertEquals(0, transportCalls.get())
        assertArrayEquals(ByteArray(3), bytes)
        assertNull(ComposeSend.current())
    }

    /** A submission arriving while a reset is still tearing down is refused, not slipped past it. */
    @Test
    fun aSubmissionDuringTeardownIsRefusedAndZeroed() {
        // A send that ignores cancellation keeps the reset waiting, which holds teardown open.
        val release = CountDownLatch(1)
        val stopping = CountDownLatch(1)
        val stubborn = object : Call by BlockingCall() {
            override fun cancel() = stopping.countDown()
        }
        val entered = CountDownLatch(1)
        ComposeSend.start(CoroutineScope(Dispatchers.IO), draft(byteArrayOf(9)), ProcessState.generation()) { _, onCall ->
            onCall(stubborn)
            entered.countDown()
            release.await(10, TimeUnit.SECONDS)
            MailOutcome.UpstreamFailure("stopped")
        }
        assertTrue(entered.await(5, TimeUnit.SECONDS))
        val reset = Thread { ProcessState.resetAll() }.apply { start() }
        assertTrue("teardown never began", stopping.await(5, TimeUnit.SECONDS))

        val bytes = byteArrayOf(4, 5, 6)
        val transportCalls = AtomicInteger()
        val late = ComposeSend.start(CoroutineScope(Dispatchers.IO), draft(bytes), ProcessState.generation()) { _, _ ->
            transportCalls.incrementAndGet()
            MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
        }
        release.countDown()
        reset.join(5_000)

        assertTrue(late.outcome.isCancelled)
        assertEquals(0, transportCalls.get())
        assertArrayEquals(ByteArray(3), bytes)
        assertNull(ComposeSend.current())
    }

    /** What a rotation relies on: with no reset, the replacement screen finds the same send. */
    @Test
    fun withoutAResetTheSendIsAdoptedAndCompletes() = runBlocking {
        val sending = ComposeSend.start(CoroutineScope(Dispatchers.IO), draft(byteArrayOf(7)), ProcessState.generation()) { _, _ ->
            MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = ""))
        }

        assertSame(sending, ComposeSend.current())
        assertTrue(sending.outcome.await() is MailOutcome.Success)
        assertArrayEquals(byteArrayOf(7), sending.draft.attachments.single().bytes)
    }
}
