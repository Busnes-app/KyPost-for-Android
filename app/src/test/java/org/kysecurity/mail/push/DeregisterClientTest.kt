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
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fakes OkHttp's [Call.Factory], mirroring PullNotificationClientTest/MfaResponseClientTest's
 *  hand-rolled-fake style (no mocking framework, no MockWebServer dependency in this repo). */
private class DeregisterFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return DeregisterFakeCall(request, responder(request))
    }
}

private class DeregisterFakeCall(private val req: Request, private val response: Response) : OfflineCall(req) {
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
    override fun clone(): Call = DeregisterFakeCall(req, response)
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

class DeregisterClientTest {

    @Test
    fun deregister_200okTrue_returnsSuccess() = runBlocking {
        val callFactory = DeregisterFakeCallFactory { request -> response(request, """{"ok": true}""", 200) }
        val client = DeregisterClient(callFactory = callFactory)

        val result = client.deregister(testPairing())

        assertTrue(result is DeregisterResult.Success)
        val sentRequest = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/notifications/native/deregister", sentRequest.url.toString())
        assertEquals("POST", sentRequest.method)
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
    }

    @Test
    fun deregister_401_returnsError() = runBlocking {
        val callFactory = DeregisterFakeCallFactory { request -> response(request, "", 401) }
        val client = DeregisterClient(callFactory = callFactory)

        val result = client.deregister(testPairing())

        assertTrue(result is DeregisterResult.Error)
    }

    @Test
    fun deregister_missingDeviceCredentials_returnsErrorWithoutNetworkCall() = runBlocking {
        val callFactory = DeregisterFakeCallFactory { request -> response(request, """{"ok": true}""", 200) }
        val client = DeregisterClient(callFactory = callFactory)

        val result = client.deregister(testPairing(deviceId = null))

        assertTrue(result is DeregisterResult.Error)
        assertTrue(callFactory.requests.isEmpty())
    }
}
