package org.kysecurity.mail.push

import org.kysecurity.mail.OfflineCall
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** What the very first registration of a pairing puts on the wire.
 *
 *  Every later registration goes through [PushSyncCoordinator.syncProvidedToken] or
 *  [PushSyncCoordinator.resyncActiveTransport], which already carry a transport and, for
 *  UnifiedPush, the RFC 8291 keys. Pairing itself did not: it sent a bare token and let the
 *  server derive the transport from `platform`, which derives `"fcm"` for anything that is not
 *  iOS. On a build with no Firebase that is wrong twice over — the server relays to a token that
 *  cannot receive, and it stores no WebPush keys, so the payload stays in the clear and the
 *  device is refused MFA challenges. */
class PairingRegistrationCredentialTest {

    /** okhttp3.Call has no test double in this module; only execute() is ever reached here. */
    private class RecordingCall(private val request: Request, private val response: Response) : OfflineCall(request) {
        override fun execute() = response
        override fun enqueue(responseCallback: okhttp3.Callback) = throw UnsupportedOperationException()
        override fun cancel() = Unit
        override fun isExecuted() = false
        override fun isCanceled() = false
        override fun clone(): okhttp3.Call = this
    }

    private val pairing = PairingData(
        subscriberId = "sub-1",
        serverUrl = "https://example.test",
        registrationUrl = "https://example.test/api/notifications/native/register",
        pairingToken = "pair-tok",
        deviceId = null,
        deviceSecret = null,
        pairedAtEpochMs = 0L,
    )

    private fun ok(request: Request) = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(200)
        .message("OK")
        .body("""{"ok":true,"synced":true,"deviceId":"dev-1","deviceSecret":"s-1"}""".toResponseBody())
        .build()

    private fun registerAndCaptureBody(credential: PushRegistrationCredential?): JsonObject? {
        var seen: JsonObject? = null
        val coordinator = PushSyncCoordinator(
            repository = FakePushStore(),
            registrationClient = NativeRegistrationClient(
                callFactory = okhttp3.Call.Factory { request ->
                    val buffer = okio.Buffer()
                    request.body?.writeTo(buffer)
                    seen = Json.parseToJsonElement(buffer.readUtf8()) as JsonObject
                    RecordingCall(request, ok(request))
                },
            ),
            wipeOnIncompletePurge = {},
            fetchRegistrationCredential = { credential },
        )
        runBlocking { coordinator.attemptPairing(pairing) }
        return seen
    }

    @Test
    fun pairing_sendsTheTransportAndKeysTheCredentialCarries() {
        val body = registerAndCaptureBody(
            PushRegistrationCredential(
                token = "https://ntfy.example/topic-1",
                transport = PushTransport.UNIFIED_PUSH,
                p256dh = "a-public-point",
                auth = "an-auth-secret",
            ),
        )

        requireNotNull(body)
        assertEquals("https://ntfy.example/topic-1", body.getValue("deviceToken").jsonPrimitive.content)
        assertEquals("unifiedpush", body.getValue("transport").jsonPrimitive.content)
        assertEquals("a-public-point", body.getValue("p256dh").jsonPrimitive.content)
        assertEquals("an-auth-secret", body.getValue("auth").jsonPrimitive.content)
    }

    /** The Firebase build names no transport, exactly as it does today, so the server keeps
     *  deriving `fcm` from `platform` and nothing about that pairing changes. */
    @Test
    fun pairing_omitsTheTransportWhenTheCredentialNamesNone() {
        val body = registerAndCaptureBody(PushRegistrationCredential(token = "fcm-token"))

        requireNotNull(body)
        assertEquals("fcm-token", body.getValue("deviceToken").jsonPrimitive.content)
        assertEquals(false, body.containsKey("transport"))
        assertEquals(false, body.containsKey("p256dh"))
        assertEquals(false, body.containsKey("auth"))
    }

    /** No distributor on a Firebase-free build means no credential, and pairing must stop rather
     *  than register something that cannot receive. */
    @Test
    fun pairing_failsWhenNoCredentialCanBeObtained() {
        val body = registerAndCaptureBody(null)

        assertNull(body)
    }
}
