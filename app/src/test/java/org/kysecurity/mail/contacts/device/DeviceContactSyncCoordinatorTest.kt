package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import java.util.concurrent.atomic.AtomicInteger
import kotlin.test.Test
import kotlin.test.assertEquals

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
}
