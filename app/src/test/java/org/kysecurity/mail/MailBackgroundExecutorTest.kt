package org.kysecurity.mail

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger

/** The wipe's anti-resurrection ordering is only worth anything if `quiesce()` really closes the
 *  lane. It used to install a fresh pool on the way out, so the window it was supposed to shut —
 *  between "stop mail work" and "the database is deleted" — was open the whole time. */
class MailBackgroundExecutorTest {

    /** Leaves the shared object usable for whatever test runs next, however this one ends. */
    @After
    fun restore() {
        repeat(4) { MailBackgroundExecutor.resume() }
    }

    private fun runsATask(): Boolean {
        val ran = CountDownLatch(1)
        MailBackgroundExecutor.submit { ran.countDown() }
        return ran.await(2, TimeUnit.SECONDS)
    }

    @Test
    fun submittedWorkRunsWhileTheExecutorIsLive() {
        assertTrue("a submission outside a quiesce must run", runsATask())
    }

    @Test
    fun submissionsWhileQuiescedAreDroppedAndDoNotThrow() {
        MailBackgroundExecutor.quiesce()

        val ran = AtomicBoolean(false)
        // Throwing here is not an acceptable refusal either: the submitter is a UI thread handling
        // a notification tap, and `RejectedExecutionException` on it is a crash, not a no-op.
        MailBackgroundExecutor.submit { ran.set(true) }
        Thread.sleep(100)

        assertFalse("work submitted during a wipe must not run", ran.get())
    }

    @Test
    fun workResumesOnlyAfterTheOutermostQuiesceIsReleased() {
        // The wipe quiesces, and its database step quiesces again inside it.
        MailBackgroundExecutor.quiesce()
        MailBackgroundExecutor.quiesce()

        MailBackgroundExecutor.resume()
        val ran = AtomicBoolean(false)
        MailBackgroundExecutor.submit { ran.set(true) }
        Thread.sleep(100)
        assertFalse("the inner scope's release must not reopen the lane", ran.get())

        MailBackgroundExecutor.resume()
        assertTrue("the outermost release must put mail work back", runsATask())
    }

    /** An unbalanced resume must not hand out a pool the enclosing wipe still wants suspended, and
     *  must not wedge mail work off for the life of the process either. */
    @Test
    fun surplusResumesDoNotUnbalanceTheNextQuiesce() {
        repeat(3) { MailBackgroundExecutor.resume() }

        MailBackgroundExecutor.quiesce()
        val ran = AtomicBoolean(false)
        MailBackgroundExecutor.submit { ran.set(true) }
        Thread.sleep(100)
        assertFalse("a stray resume must not have cancelled a real quiesce", ran.get())

        MailBackgroundExecutor.resume()
        assertTrue(runsATask())
    }

    /** A submitter that claimed state for its task (a hidden row) must hear that the task never ran. */
    @Test
    fun aRefusedSubmissionReportsItsDrop() {
        MailBackgroundExecutor.quiesce()
        val dropped = AtomicBoolean(false)

        MailBackgroundExecutor.submit(onDropped = { dropped.set(true) }) {}

        assertTrue(dropped.get())
    }

    @Test
    fun aQueuedTaskDiscardedByQuiesceReportsItsDrop() {
        val hold = CountDownLatch(1)
        val busy = CountDownLatch(2)
        // Both pool threads busy, so the third task waits in the queue.
        repeat(2) { MailBackgroundExecutor.submit { busy.countDown(); hold.await(5, TimeUnit.SECONDS) } }
        assertTrue(busy.await(5, TimeUnit.SECONDS))
        val dropped = AtomicBoolean(false)
        val ran = AtomicBoolean(false)
        MailBackgroundExecutor.submit(onDropped = { dropped.set(true) }) { ran.set(true) }

        MailBackgroundExecutor.quiesce()
        hold.countDown()

        assertTrue(dropped.get())
        assertFalse(ran.get())
    }

    /** The race the wipe actually loses: submissions still arriving while the teardown runs. Not
     *  one of them may start after `quiesce()` returns, which is the instant its caller closes the
     *  database and deletes the file. */
    @Test
    fun nothingStartsAfterQuiesceReturns() {
        val quiesced = AtomicBoolean(false)
        val done = AtomicBoolean(false)
        val startedTooLate = AtomicInteger(0)
        val rejections = AtomicInteger(0)
        val go = CountDownLatch(1)

        val submitters = (1..4).map {
            Thread {
                go.await()
                while (!done.get()) {
                    runCatching {
                        MailBackgroundExecutor.submit {
                            if (quiesced.get()) startedTooLate.incrementAndGet()
                        }
                    }.onFailure { rejections.incrementAndGet() }
                    Thread.sleep(1)
                }
            }.apply { start() }
        }

        go.countDown()
        Thread.sleep(50)
        MailBackgroundExecutor.quiesce()
        quiesced.set(true)
        // Submissions go on arriving through exactly the window a wipe spends deleting the file.
        Thread.sleep(150)
        done.set(true)
        submitters.forEach { it.join(5_000) }
        MailBackgroundExecutor.resume()

        assertEquals("a task ran against a database the wipe had already deleted", 0, startedTooLate.get())
        assertEquals("submitting during a wipe threw at the caller", 0, rejections.get())
    }
}
