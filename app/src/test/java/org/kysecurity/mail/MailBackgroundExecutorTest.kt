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

    private val order = java.util.Collections.synchronizedList(mutableListOf<String>())

    /** A read ordered first and still running holds back an unread ordered after it, whichever
     *  pool thread each lands on: unordered, the unread would reach the relay first and be undone. */
    @Test
    fun anOrderedTaskWaitsForTheOneOrderedBeforeIt() {
        val release = CountDownLatch(1)
        val read = ReadStateLane.ordered { release.await(); order += "read" }
        val unread = ReadStateLane.ordered { order += "unread" }
        val unreadThread = Thread { unread() }.apply { start() }
        val readThread = Thread { read() }.apply { start() }

        unreadThread.join(200)
        assertTrue("unread must wait for read", unreadThread.isAlive)
        release.countDown()
        readThread.join(2_000)
        unreadThread.join(2_000)

        assertEquals(listOf("read", "unread"), order)
    }

    /** Every request waits for the one before it, not just a read on the same screen. */
    @Test
    fun aChainOfOrderedTasksRunsInRequestOrder() {
        val tasks = (1..4).map { n -> ReadStateLane.ordered { order += "$n" } }
        val threads = tasks.reversed().map { task -> Thread { task() }.apply { start() } }
        threads.forEach { it.join(2_000) }

        assertEquals(listOf("1", "2", "3", "4"), order)
    }

    @Test
    fun anOrderedTaskGivesUpOnAHungPredecessorAndRunsAnyway() {
        val release = CountDownLatch(1)
        val hung = ReadStateLane.ordered { release.await() }
        val hungThread = Thread { hung() }.apply { start() }

        assertEquals("ran", ReadStateLane.ordered(waitSeconds = 0) { "ran" }())
        release.countDown()
        hungThread.join(2_000)
    }

    /** A wipe quiesces the pool by interrupting it; the waiting mutation must not then run. */
    @Test
    fun anOrderedTaskStopsWhenInterrupted() {
        val release = CountDownLatch(1)
        val read = ReadStateLane.ordered { release.await() }
        val readThread = Thread { read() }.apply { start() }
        val unread = ReadStateLane.ordered { order += "unread" }
        val failure = java.util.concurrent.atomic.AtomicReference<Throwable>()
        val unreadThread = Thread { runCatching { unread() }.onFailure(failure::set) }.apply { start() }

        unreadThread.join(200)
        unreadThread.interrupt()
        unreadThread.join(2_000)
        release.countDown()
        readThread.join(2_000)

        assertTrue(failure.get() is InterruptedException)
        assertFalse("unread" in order)
    }
}
