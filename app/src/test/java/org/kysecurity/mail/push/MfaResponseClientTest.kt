package org.kysecurity.mail.push

import org.kysecurity.mail.OfflineCall
import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.HEADER_DEVICE_SECRET
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fakes OkHttp's [Call.Factory], mirroring PullNotificationClientTest/RelayMailSourceTest's
 *  hand-rolled-fake style (no mocking framework, no MockWebServer dependency in this repo). */
private class MfaFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        val buffer = okio.Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return MfaFakeCall(request, responder(request))
    }
}

private class MfaFakeCall(private val req: Request, private val response: Response) : OfflineCall(req) {
    private var executed = false
    private var canceled = false
    override fun execute(): Response {
        executed = true
        return response
    }
    override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(this, response)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = canceled
    override fun clone(): Call = MfaFakeCall(req, response)
}

private fun response(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

private fun testPairing(deviceId: String? = "device-1", deviceSecret: String? = "secret-1") = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = deviceId,
    deviceSecret = deviceSecret,
    pairedAtEpochMs = 0L,
)

class MfaResponseClientTest {

    @Test
    fun respond_200_sendsSlimBodyAndDeviceHeaders() = runBlocking {
        val callFactory = MfaFakeCallFactory { request -> response(request, """{"ok": true, "status": "approved"}""", 200) }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(), challengeId = "challenge-1", approve = true, matchDigits = "47")

        assertTrue(result is MfaRespondResult.Success)
        assertEquals("approved", (result as MfaRespondResult.Success).status)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))

        val sentBody = callFactory.bodies.single()
        assertFalse(sentBody.contains("subscriberId"))
        assertFalse(sentBody.contains("subscriberHash"))
        assertFalse(sentBody.contains("\"deviceId\""))
        assertTrue(sentBody.contains("\"challengeId\":\"challenge-1\""))
        assertTrue(sentBody.contains("\"approve\":true"))
    }

    /** The server verifies the number server-side and refuses an approval without it
     *  (kypost-server ResolvePushWithMatch), so it has to be on the wire. */
    @Test
    fun respond_approve_putsMatchDigitsOnTheWire() = runBlocking {
        val callFactory = MfaFakeCallFactory { request -> response(request, """{"ok": true, "status": "approved"}""", 200) }
        val client = MfaResponseClient(callFactory = callFactory)

        client.respond(testPairing(), challengeId = "challenge-1", approve = true, matchDigits = "47")

        assertTrue(callFactory.bodies.single().contains("\"matchDigits\":\"47\""))
    }

    /** Deny must never require the number: the person most likely to press it is someone being
     *  MFA-fatigued, looking at a number they cannot match. The server ignores the field on a deny. */
    @Test
    fun respond_deny_sendsEmptyMatchDigits() = runBlocking {
        val callFactory = MfaFakeCallFactory { request -> response(request, """{"ok": true, "status": "denied"}""", 200) }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(), challengeId = "challenge-1", approve = false)

        assertTrue(result is MfaRespondResult.Success)
        val sentBody = callFactory.bodies.single()
        assertTrue(sentBody.contains("\"approve\":false"))
        assertTrue(sentBody.contains("\"matchDigits\":\"\""))
    }

    @Test
    fun respond_400_reportsTheServerMismatchMessage() = runBlocking {
        val callFactory = MfaFakeCallFactory { request ->
            response(request, """{"error": "that is not the number shown in the browser"}""", 400, "Bad Request")
        }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(), challengeId = "challenge-1", approve = true, matchDigits = "11")

        assertTrue(result is MfaRespondResult.Error)
        assertEquals("that is not the number shown in the browser", (result as MfaRespondResult.Error).message)
    }

    @Test
    fun respond_429_reportsAttemptsExhausted() = runBlocking {
        val callFactory = MfaFakeCallFactory { request ->
            response(request, """{"error": "too many incorrect attempts; start the sign-in again"}""", 429, "Too Many Requests")
        }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(), challengeId = "challenge-1", approve = true, matchDigits = "11")

        assertTrue(result is MfaRespondResult.Error)
        assertEquals("too many incorrect attempts; start the sign-in again", (result as MfaRespondResult.Error).message)
    }

    @Test
    fun respond_missingDeviceCredentials_returnsErrorWithoutNetworkCall() = runBlocking {
        val callFactory = MfaFakeCallFactory { request -> response(request, """{"ok": true}""", 200) }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(deviceId = null), challengeId = "challenge-1", approve = true)

        assertTrue(result is MfaRespondResult.Error)
        assertTrue(callFactory.requests.isEmpty())
    }

    @Test
    fun respond_401_mapsToError() = runBlocking {
        val callFactory = MfaFakeCallFactory { request -> response(request, "", 401) }
        val client = MfaResponseClient(callFactory = callFactory)

        val result = client.respond(testPairing(), challengeId = "challenge-1", approve = true)

        assertTrue(result is MfaRespondResult.Error)
    }
}
