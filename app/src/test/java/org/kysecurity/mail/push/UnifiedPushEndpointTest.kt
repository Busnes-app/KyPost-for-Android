package org.kysecurity.mail.push

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.ProcessState
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response
import kotlin.coroutines.CoroutineContext

/** A UnifiedPush endpoint is distributor state, not registration state: the distributor usually
 *  delivers it before the device is paired, and pairing has to register it. */
class UnifiedPushEndpointTest {

    private val pairing = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example",
        registrationUrl = "https://relay.example/api/notifications/native/register",
        pairingToken = "tok-1",
        deviceId = null,
        deviceSecret = null,
        pairedAtEpochMs = 0L,
    )

    private val endpoint = "https://ntfy.example/up-topic"

    private var fcmFetches = 0
    private val calls = BodyRecordingCallFactory { req ->
        response(req, """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"s-1"}""", 200)
    }

    /** Stands in for the gms channel: every fetch is an FCM token, and is counted. */
    private fun coordinator(store: FakePushStore, events: CoroutineScope = CoroutineScope(ManualDispatcher())) =
        PushSyncCoordinator(
            repository = store,
            registrationClient = NativeRegistrationClient(callFactory = calls),
            wipeOnIncompletePurge = {},
            wipeOwed = { false },
            fetchRegistrationCredential = { fcmFetches++; PushRegistrationCredential(token = "fcm-token") },
            eventScope = events,
        )

    /** Holds dispatched work until [runNewestFirst], which runs it in reverse: the worst order a
     *  thread pool could pick. */
    private class ManualDispatcher : CoroutineDispatcher() {
        private val tasks = ArrayDeque<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) { tasks.addLast(block) }
        fun runNewestFirst() { while (tasks.isNotEmpty()) tasks.removeLast().run() }
    }

    private fun lastBody(): JsonObject = Json.parseToJsonElement(calls.bodies.last()) as JsonObject

    private fun assertRegisteredUnifiedPush() {
        val body = lastBody()
        assertEquals(endpoint, body["deviceToken"]?.jsonPrimitive?.content)
        assertEquals(PushTransport.UNIFIED_PUSH.wire, body["transport"]?.jsonPrimitive?.content)
        assertEquals("p256dh-1", body["p256dh"]?.jsonPrimitive?.content)
        assertEquals("auth-1", body["auth"]?.jsonPrimitive?.content)
        assertEquals("no FCM token may be fetched", 0, fcmFetches)
    }

    @Test
    fun anEndpointDeliveredBeforePairingIsWhatPairingRegisters() = runBlocking {
        val store = FakePushStore()
        val coordinator = coordinator(store)

        coordinator.acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", ProcessState.generation())
        assertTrue("nothing is registered while unpaired", calls.bodies.isEmpty())

        val result = coordinator.attemptPairing(pairing)

        assertTrue("pairing failed: $result", result is NativeRegistrationResult.Success)
        assertRegisteredUnifiedPush()

        // And every later resync stays on it.
        coordinator.resyncActiveTransport()
        assertEquals(2, calls.bodies.size)
        assertRegisteredUnifiedPush()
    }

    /** The replacement branch purges the old account after registering; the endpoint it just
     *  registered must survive that purge, or the next resync falls back to FCM. */
    @Test
    fun aReplacementPairingKeepsTheEndpointItRegistered() = runBlocking {
        val store = FakePushStore(pairing = pairing.copy(subscriberId = "sub-old", deviceSecret = "old"))
        val coordinator = coordinator(store)
        coordinator.acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", ProcessState.generation())

        coordinator.attemptPairing(pairing)

        assertRegisteredUnifiedPush()
        assertEquals(endpoint, store.state.first().unifiedPushEndpoint)
    }

    /** onUnregistered: the distributor revoked the endpoint, so it must never be registered. */
    @Test
    fun aForgottenEndpointIsNeverRegistered() = runBlocking {
        val store = FakePushStore()
        val coordinator = coordinator(store)
        coordinator.acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", ProcessState.generation())

        coordinator.forgetUnifiedPushEndpoint(ProcessState.generation())
        coordinator.attemptPairing(pairing)

        assertEquals("fcm-token", lastBody()["deviceToken"]?.jsonPrimitive?.content)
        assertEquals(null, store.state.first().unifiedPushEndpoint)
    }

    /** An unpair or wipe ends the session the callback was captured in; its endpoint must not land. */
    @Test
    fun anEndpointFromAnEndedSessionIsNeitherStoredNorRegistered() = runBlocking {
        val store = FakePushStore(pairing = pairing.copy(deviceId = "dev-1", deviceSecret = "s-0"))
        val coordinator = coordinator(store)
        val captured = ProcessState.generation()

        ProcessState.advanceGeneration()
        coordinator.acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", captured)

        assertEquals(null, store.state.first().unifiedPushEndpoint)
        assertTrue("nothing may be registered", calls.bodies.isEmpty())
    }

    /** onNewEndpoint then onUnregistered: however the work is scheduled, the revocation wins. */
    @Test
    fun aRevocationIsNeverOvertakenByTheEndpointItRevokes() = runBlocking {
        val store = FakePushStore()
        val dispatcher = ManualDispatcher()
        val coordinator = coordinator(store, CoroutineScope(dispatcher))

        coordinator.enqueueUnifiedPush {
            acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", ProcessState.generation())
        }
        coordinator.enqueueUnifiedPush { forgetUnifiedPushEndpoint(ProcessState.generation()) }
        dispatcher.runNewestFirst()

        assertEquals(null, store.state.first().unifiedPushEndpoint)
        coordinator.attemptPairing(pairing)
        assertEquals("fcm-token", lastBody()["deviceToken"]?.jsonPrimitive?.content)
    }

    /** A revocation queued before a relaunch must not clear the endpoint the new session stored. */
    @Test
    fun aRevocationFromAnEndedSessionLeavesTheNewEndpoint() = runBlocking {
        val store = FakePushStore()
        val oldEvents = ManualDispatcher()
        val old = coordinator(store, CoroutineScope(oldEvents))
        val captured = ProcessState.generation()
        old.enqueueUnifiedPush { forgetUnifiedPushEndpoint(captured) }

        ProcessState.advanceGeneration()
        coordinator(store).acceptUnifiedPushEndpoint(endpoint, "p256dh-1", "auth-1", ProcessState.generation())
        oldEvents.runNewestFirst()

        val state = store.state.first()
        assertEquals(endpoint, state.unifiedPushEndpoint)
        assertEquals("p256dh-1", state.unifiedPushP256dh)
        assertEquals("auth-1", state.unifiedPushAuth)
    }
}
