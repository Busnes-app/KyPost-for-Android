package org.kysecurity.mail.push

import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

/**
 * The push-mode heartbeat.
 *
 * The server queues every notification in both modes and never flips the mode itself, so a device
 * on a dead relay recovers only by polling. In PUSH mode the coordinator polls once the transport
 * has been quiet past [PullSyncCoordinator.PUSH_QUIET_THRESHOLD_MS], and not before.
 */
class PullHeartbeatTest {

    private val pairing = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private val threshold = PullSyncCoordinator.PUSH_QUIET_THRESHOLD_MS
    private val now = 10 * threshold

    private class Harness(store: FakePushStore, now: Long, body: String) {
        val requests = AtomicInteger()
        val shown = mutableListOf<IncomingPush>()
        val armed = AtomicInteger()
        val coordinator = PullSyncCoordinator(
            repository = store,
            pullClient = PullNotificationClient(
                callFactory = FakeCallFactory { req ->
                    requests.incrementAndGet()
                    response(req, body, 200)
                },
            ),
            notifier = { shown += it },
            ensurePeriodic = { armed.incrementAndGet() },
            clock = { now },
        )
    }

    private fun pushModeStore(lastPushAt: Long?): FakePushStore = FakePushStore(pairing = pairing).also {
        runBlocking {
            it.updateDelivery(DeliveryMode.PUSH, null)
            it.updateSyncState(lastSyncAtEpochMs = 0L, syncError = null)
            if (lastPushAt != null) it.markPushReceived(lastPushAt)
        }
    }

    private fun queued(seq: Long, messageId: String, createdAtEpochMs: Long) = """
        {"seq":$seq,"title":"Sender","body":"Subject","data":{"messageId":"$messageId"},
         "createdAt":"${java.time.Instant.ofEpochMilli(createdAtEpochMs)}"}
    """.trimIndent()

    @Test
    fun pushModeWithARecentPush_skipsTheNetworkButKeepsTheWorkerArmed() = runBlocking {
        val store = pushModeStore(lastPushAt = now - threshold + 1)
        val h = Harness(store, now, """{"deliveryMode":"push","cursor":0,"notifications":[]}""")

        assertEquals(PullOutcome.PushHealthy, h.coordinator.pullOnce())
        assertEquals(0, h.requests.get())
        assertEquals(1, h.armed.get())
    }

    @Test
    fun pushModeQuietPastTheThreshold_pollsAndDeliversWhatPushMissed() = runBlocking {
        val store = pushModeStore(lastPushAt = now - threshold)
        val body = """{"deliveryMode":"push","cursor":2,"notifications":[
            ${queued(1, "msg-1", now - threshold)}, ${queued(2, "msg-2", now - 1)}]}"""
        val h = Harness(store, now, body)

        assertEquals(PullOutcome.Pulled(2), h.coordinator.pullOnce())
        assertEquals(1, h.requests.get())
        assertEquals(listOf("msg-1", "msg-2"), h.shown.map { (it as IncomingPush.Mail).payload.messageId })
        assertEquals(2L, store.cursor)
        // A PUSH answer is not "stop polling": the mode stays and the worker stays armed.
        assertEquals(DeliveryMode.PUSH, store.currentDeliveryMode())
        assertEquals(1, h.armed.get())
    }

    /** No push ever seen: the registration time is the clock, so a fresh pairing gets the threshold. */
    @Test
    fun pushModeNeverPushed_countsFromRegistration() = runBlocking {
        val store = FakePushStore(pairing = pairing)
        store.updateDelivery(DeliveryMode.PUSH, null)
        store.updateSyncState(lastSyncAtEpochMs = now - threshold + 1, syncError = null)
        val h = Harness(store, now, """{"deliveryMode":"push","cursor":0,"notifications":[]}""")

        assertEquals(PullOutcome.PushHealthy, h.coordinator.pullOnce())
        assertEquals(0, h.requests.get())
    }

    /** A stale cursor returns months of push-delivered mail; only the recent tail is surfaced. */
    @Test
    fun heartbeat_dropsEntriesOlderThanTwiceTheThreshold_butAdvancesPastThem() = runBlocking {
        val store = pushModeStore(lastPushAt = 0L)
        val body = """{"deliveryMode":"push","cursor":2,"notifications":[
            ${queued(1, "ancient", now - 2 * threshold - 1)}, ${queued(2, "recent", now - 2 * threshold)}]}"""
        val h = Harness(store, now, body)

        h.coordinator.pullOnce()
        assertEquals(listOf("recent"), h.shown.map { (it as IncomingPush.Mail).payload.messageId })
        assertEquals(2L, store.cursor)
    }

    @Test
    fun pullMode_pollsRegardlessOfPushRecency_andKeepsOldEntries() = runBlocking {
        val store = FakePushStore(pairing = pairing)
        store.updateDelivery(DeliveryMode.PULL, null)
        store.markPushReceived(now)
        val body = """{"deliveryMode":"pull","cursor":1,"notifications":[${queued(1, "old", 0L)}]}"""
        val h = Harness(store, now, body)

        assertEquals(PullOutcome.Pulled(1), h.coordinator.pullOnce())
        assertEquals(1, h.requests.get())
        assertTrue(h.shown.single() is IncomingPush.Mail)
    }

    /** Push already delivered it: history says so, and the user is not alerted twice. */
    @Test
    fun heartbeat_doesNotReAlertMailAlreadyInHistory() = runBlocking {
        val store = pushModeStore(lastPushAt = 0L)
        store.knownMessageIds += "msg-1"
        val body = """{"deliveryMode":"push","cursor":1,"notifications":[${queued(1, "msg-1", now)}]}"""
        val h = Harness(store, now, body)

        assertEquals(PullOutcome.Pulled(1), h.coordinator.pullOnce())
        assertTrue(h.shown.isEmpty())
        assertEquals(1L, store.cursor)
    }
}
