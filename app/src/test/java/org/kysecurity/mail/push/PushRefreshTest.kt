package org.kysecurity.mail.push

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response

/** Owner decision Q1 A: a paired device resyncs through `native/refresh` with its own device
 *  secret, because the pairing token `native/register` needs is single-use and lives 90 s. An
 *  older server without the route (404) gets today's register. */
class PushRefreshTest {

    private val paired = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://relay.example",
        registrationUrl = "https://relay.example/api/notifications/native/register",
        pairingToken = "tok-1",
        deviceId = "dev-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    private fun coordinator(store: FakePushStore, calls: BodyRecordingCallFactory) = PushSyncCoordinator(
        repository = store,
        registrationClient = NativeRegistrationClient(callFactory = calls),
        wipeOnIncompletePurge = {},
        wipeOwed = { false },
        fetchRegistrationCredential = { PushRegistrationCredential(token = "fcm-token-2") },
    )

    private fun answering(refreshCode: Int, refreshBody: String) = BodyRecordingCallFactory { req ->
        if (req.url.encodedPath.endsWith("/native/refresh")) {
            response(req, refreshBody, refreshCode)
        } else {
            response(req, """{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"secret-2"}""", 200)
        }
    }

    @Test
    fun aResyncRefreshesWithTheDeviceSecretAndKeepsIt() = runBlocking {
        val store = FakePushStore(pairing = paired)
        val calls = answering(200, """{"ok":true,"deviceId":"dev-1","transport":"fcm"}""")

        val result = coordinator(store, calls).syncCurrentPairingToken()

        assertTrue("refresh failed: $result", result is NativeRegistrationResult.Success)
        val request = calls.requests.single()
        assertTrue(request.url.toString(), request.url.encodedPath.endsWith("/api/notifications/native/refresh"))
        assertEquals("dev-1", request.header("X-Kypost-Device-Id"))
        assertEquals("secret-1", request.header("X-Kypost-Device-Secret"))
        val body = Json.parseToJsonElement(calls.bodies.single()) as JsonObject
        assertEquals("\"fcm-token-2\"", body["deviceToken"].toString())
        assertFalse("no pairing token on refresh", body.containsKey("pairingToken"))
        assertEquals("secret-1", store.currentPairing()?.deviceSecret)
    }

    @Test
    fun anOlderServerWithoutTheRouteFallsBackToRegister() = runBlocking {
        val store = FakePushStore(pairing = paired)
        val calls = answering(404, "404 page not found")

        val result = coordinator(store, calls).syncCurrentPairingToken()

        assertTrue("register failed: $result", result is NativeRegistrationResult.Success)
        assertEquals(2, calls.requests.size)
        assertTrue(calls.requests[1].url.encodedPath.endsWith("/native/register"))
        assertEquals("secret-2", store.currentPairing()?.deviceSecret)
    }

    @Test
    fun aRevokedDeviceIsToldToRescanAndNeverReRegisters() = runBlocking {
        val store = FakePushStore(pairing = paired)
        val calls = answering(401, """{"error":"unauthorized"}""")

        val result = coordinator(store, calls).syncCurrentPairingToken()

        assertTrue((result as NativeRegistrationResult.Error).expiredPairingToken)
        assertEquals(1, calls.requests.size)
        assertEquals("secret-1", store.currentPairing()?.deviceSecret)
    }
}
