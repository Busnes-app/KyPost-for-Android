package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DeviceContactSyncCoordinatorTest {

    /** The running pass may already have read past the change that triggered the second request. */
    @Test
    fun aRequestDuringASync_runsAnotherPassAfterIt() = runBlocking {
        val started = Channel<Int>(Channel.UNLIMITED)
        val release = CompletableDeferred<Unit>()
        val runs = AtomicInteger()
        val coordinator = DeviceContactSyncCoordinator(
            syncAll = {
                val run = runs.incrementAndGet()
                started.send(run)
                if (run == 1) release.await()
                emptyList()
            },
            enabled = { true },
        )

        coordinator.syncNowAsync()
        withTimeout(5_000) { started.receive() }
        coordinator.syncNowAsync()
        coordinator.syncNowAsync()
        release.complete(Unit)

        assertEquals(2, withTimeout(5_000) { started.receive() })
    }

    /** The request and the running pass's decision to stop must not interleave: a requester stalled
     *  after finding a pass running, while that pass finishes, still gets its pass. */
    @Test
    fun aRequestRacingTheEndOfAPass_stillGetsAPass() = runBlocking {
        val scope = kotlinx.coroutines.CoroutineScope(kotlinx.coroutines.SupervisorJob() + kotlinx.coroutines.Dispatchers.Default)
        val runs = AtomicInteger()
        val firstStarted = CompletableDeferred<Unit>()
        val releaseFirst = CompletableDeferred<Unit>()
        val requesterStalled = java.util.concurrent.CountDownLatch(1)
        val resumeRequester = java.util.concurrent.CountDownLatch(1)
        val coordinator = DeviceContactSyncCoordinator(
            syncAll = {
                if (runs.incrementAndGet() == 1) {
                    firstStarted.complete(Unit)
                    releaseFirst.await()
                }
                emptyList()
            },
            enabled = { true },
            scope = scope,
            onFoundRunning = {
                requesterStalled.countDown()
                resumeRequester.await(WAIT_S, java.util.concurrent.TimeUnit.SECONDS)
            },
        )
        suspend fun joinPasses() =
            withTimeout(WAIT_S * 1_000) { scope.coroutineContext[kotlinx.coroutines.Job]!!.children.forEach { it.join() } }

        var requester: Thread? = null
        try {
            coordinator.syncNowAsync()
            withTimeout(WAIT_S * 1_000) { firstStarted.await() }
            requester = kotlin.concurrent.thread { coordinator.syncNowAsync() }
            assertTrue(requesterStalled.await(WAIT_S, java.util.concurrent.TimeUnit.SECONDS), "requester never reached the running pass")
            releaseFirst.complete(Unit)
            joinPasses()
            resumeRequester.countDown()
            requester.join(WAIT_S * 1_000)
            assertFalse(requester.isAlive, "requester did not finish")
            joinPasses()
        } finally {
            // Whatever failed above, nothing may be left blocked or running for the next test.
            resumeRequester.countDown()
            releaseFirst.complete(Unit)
            scope.cancel()
            requester?.join(WAIT_S * 1_000)
        }

        assertEquals(2, runs.get())
    }

    private companion object {
        const val WAIT_S = 5L
    }

    /** A pass queued while sync was on must not run once sync is off: turning device sync off,
     *  or Hostile Location Protection on, means no further pass touches the contacts provider. */
    @Test
    fun aDebouncedPass_doesNotRunAfterSyncIsTurnedOff() = runBlocking {
        val runs = AtomicInteger()
        var on = true
        val coordinator = DeviceContactSyncCoordinator(
            syncAll = { runs.incrementAndGet(); emptyList() },
            enabled = { on },
            debounceMs = 50,
        )

        coordinator.syncWithDebounce()
        on = false
        kotlinx.coroutines.delay(500)

        assertEquals(0, runs.get())
    }

    /** The same for Hostile Location Protection turned on during the debounce. */
    @Test
    fun aDebouncedPass_doesNotRunOnceProtectionIsOn() = runBlocking {
        val runs = AtomicInteger()
        var protectionOn = false
        val coordinator = DeviceContactSyncCoordinator(
            syncAll = { runs.incrementAndGet(); emptyList() },
            enabled = { true },
            hostileLocationEnabled = { protectionOn },
            debounceMs = 50,
        )

        coordinator.syncWithDebounce()
        protectionOn = true
        kotlinx.coroutines.delay(500)

        assertEquals(0, runs.get())
    }

    /** A closed coordinator, its graph dropped, runs nothing it had queued. */
    @Test
    fun close_stopsAQueuedPass() = runBlocking {
        val runs = AtomicInteger()
        val coordinator = DeviceContactSyncCoordinator(
            syncAll = { runs.incrementAndGet(); emptyList() },
            enabled = { true },
            debounceMs = 50,
        )

        coordinator.syncWithDebounce()
        coordinator.close()
        kotlinx.coroutines.delay(500)

        assertEquals(0, runs.get())
    }
}
