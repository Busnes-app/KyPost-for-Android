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
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** Fakes OkHttp's [Call.Factory], mirroring RelayMailSourceTest/ContactSyncClientTest's
 *  hand-rolled-fake style (no mocking framework, no MockWebServer dependency in this repo). */
private class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

private class FakeCall(private val req: Request, private val response: Response) : OfflineCall(req) {
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
    override fun clone(): Call = FakeCall(req, response)
}

private fun response(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class PullNotificationClientTest {

    @Test
    fun pull_200_sendsPairingHeaders_notQueryParams() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"notifications": [], "cursor": 0}""", 200)
        }
        val client = PullNotificationClient(callFactory = callFactory)

        val result = client.pull(
            pullEndpoint = "https://relay.example.com/api/notifications/native/pull",
            deviceId = "device-1",
            deviceSecret = "secret-1",
            afterCursor = 0L,
        )

        assertTrue(result is PullResult.Success)
        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("device"))
        assertNull(sentRequest.url.queryParameter("secret"))
        assertEquals("0", sentRequest.url.queryParameter("after"))
    }
}
