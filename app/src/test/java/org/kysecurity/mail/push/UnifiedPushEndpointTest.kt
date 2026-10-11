package org.kysecurity.mail.push

import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response

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
    private fun coordinator(store: FakePushStore) = PushSyncCoordinator(
        repository = store,
        registrationClient = NativeRegistrationClient(callFactory = calls),
        wipeOnIncompletePurge = {},
        fetchRegistrationCredential = { fcmFetches++; PushRegistrationCredential(token = "fcm-token") },
    )

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

        // What KyPostUnifiedPushService.onNewEndpoint does.
        coordinator.syncProvidedToken(endpoint, PushTransport.UNIFIED_PUSH, "p256dh-1", "auth-1")
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
        coordinator.syncProvidedToken(endpoint, PushTransport.UNIFIED_PUSH, "p256dh-1", "auth-1")

        coordinator.attemptPairing(pairing)

        assertRegisteredUnifiedPush()
        assertEquals(endpoint, store.state.first().unifiedPushEndpoint)
    }

    /** onUnregistered: the distributor revoked the endpoint, so it must never be registered. */
    @Test
    fun aForgottenEndpointIsNeverRegistered() = runBlocking {
        val store = FakePushStore()
        val coordinator = coordinator(store)
        coordinator.syncProvidedToken(endpoint, PushTransport.UNIFIED_PUSH, "p256dh-1", "auth-1")

        coordinator.forgetUnifiedPushEndpoint()
        coordinator.attemptPairing(pairing)

        assertEquals("fcm-token", lastBody()["deviceToken"]?.jsonPrimitive?.content)
        assertEquals(null, store.state.first().unifiedPushEndpoint)
    }
}
