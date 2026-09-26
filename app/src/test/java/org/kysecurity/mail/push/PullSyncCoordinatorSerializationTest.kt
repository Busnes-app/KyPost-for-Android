package org.kysecurity.mail.push

import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Collections
import java.util.concurrent.BrokenBarrierException
import java.util.concurrent.CyclicBarrier
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * One pull at a time.
 *
 * The cursor is read at the start of a pull and advanced at the end. App foreground, the pairing
 * screen and [PullWorker] all enter independently, so two overlapping runs read the same cursor
 * and both hand the same batch to the notification manager — which, unlike push history, does not
 * deduplicate by `messageId`.
 */
class PullSyncCoordinatorSerializationTest {

    private val pairing = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private val oneNotification = """
        {"deliveryMode":"pull","cursor":1,
         "notifications":[{"seq":1,"title":"Sender","body":"Subject","data":{"messageId":"msg-1"}}]}
    """.trimIndent()

    @Test
    fun overlappingPullsNotifyEachMessageOnce() = runBlocking {
        val store = FakePushStore(pairing = pairing)
        store.updateDelivery(DeliveryMode.PULL, "https://relay.example.com/api/notifications/pull")
        val shown = Collections.synchronizedList(mutableListOf<PushPayload>())
        // Trips only if two pulls are in flight together; otherwise it just times out and breaks.
        val overlapProbe = CyclicBarrier(2)
        val overlapped = AtomicBoolean(false)

        val coordinator = PullSyncCoordinator(
            repository = store,
            pullClient = PullNotificationClient(
                callFactory = FakeCallFactory { req ->
                    runCatching { overlapProbe.await(500, TimeUnit.MILLISECONDS) }
                        .onSuccess { overlapped.set(true) }
                        .onFailure {
                            if (it !is BrokenBarrierException && it !is java.util.concurrent.TimeoutException) throw it
                        }
                    response(req, oneNotification, 200)
                },
            ),
            notifier = { incoming -> shown += (incoming as IncomingPush.Mail).payload },
            ensurePeriodic = {},
        )

        listOf(
            async(Dispatchers.IO) { coordinator.pullOnce() },
            async(Dispatchers.IO) { coordinator.pullOnce() },
        ).awaitAll()

        assertTrue("two pulls were in flight at once", !overlapped.get())
        // The second pull reads the cursor the first advanced, so its batch is empty.
        assertEquals(listOf("msg-1"), shown.map { it.messageId })
        assertEquals(1L, store.cursor)
    }

    /** The read/advance pair is what must not interleave, so pin the order down directly. */
    @Test
    fun theCursorIsAdvancedBeforeTheNextPullReadsIt() = runBlocking {
        val store = FakePushStore(pairing = pairing)
        store.updateDelivery(DeliveryMode.PULL, "https://relay.example.com/api/notifications/pull")
        val coordinator = PullSyncCoordinator(
            repository = store,
            pullClient = PullNotificationClient(
                callFactory = FakeCallFactory { req -> response(req, oneNotification, 200) },
            ),
            notifier = {},
            ensurePeriodic = {},
        )

        listOf(
            async(Dispatchers.IO) { coordinator.pullOnce() },
            async(Dispatchers.IO) { coordinator.pullOnce() },
        ).awaitAll()

        val cursorEvents = store.events.filter { it.startsWith("readCursor") || it.startsWith("advanceCursor") }
        assertEquals(
            listOf("readCursor:0", "advanceCursor:1", "readCursor:1", "advanceCursor:1"),
            cursorEvents,
        )
    }
}
