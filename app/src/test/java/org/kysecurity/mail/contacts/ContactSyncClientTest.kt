package org.kysecurity.mail.contacts

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
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** Fakes OkHttp's [Call.Factory], mirroring RelayMailSourceTest's hand-rolled-fake style (no
 *  mocking framework, no MockWebServer dependency in this repo). */
private class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

private class ThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = ThrowingCall(request, exception)
}

private class FakeCall(private val req: Request, private val response: Response) : Call {
    private var executed = false
    private var canceled = false
    override fun request(): Request = req
    override fun execute(): Response {
        executed = true
        return response
    }
    override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(this, response)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = canceled
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = FakeCall(req, response)
}

private class ThrowingCall(private val req: Request, private val exception: Exception) : Call {
    override fun request(): Request = req
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = ThrowingCall(req, exception)
}

private fun response(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class ContactSyncClientTest {

    @Test
    fun dedupe_200_decodesReportAndSendsExpectedRequest() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(
                request,
                """{"mergedCount": 2, "groups": [{"survivor": "uid-1", "absorbed": ["uid-2", "uid-3"]}]}""",
                200,
            )
        }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com/", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Success)
        val report = (result as ContactDedupeResult.Success).report
        assertEquals(2, report.mergedCount)
        assertEquals(listOf(ContactDedupeGroupDto(survivor = "uid-1", absorbed = listOf("uid-2", "uid-3"))), report.groups)

        val sentRequest = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/contacts/dedupe", sentRequest.url.newBuilder().query(null).build().toString())
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("device"))
        assertNull(sentRequest.url.queryParameter("secret"))
        assertEquals("POST", sentRequest.method)
    }

    @Test
    fun dedupe_200_zeroMergedCount_isStillSuccess() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, """{"mergedCount": 0, "groups": []}""", 200) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Success)
        assertEquals(0, (result as ContactDedupeResult.Success).report.mergedCount)
    }

    @Test
    fun dedupe_400_mapsToBadRequest() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "bad params", 400) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.BadRequest)
        assertEquals("bad params", (result as ContactDedupeResult.BadRequest).message)
    }

    @Test
    fun dedupe_401_mapsToUnauthorized() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 401) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Unauthorized)
    }

    @Test
    fun dedupe_503_mapsToServiceUnavailable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 503) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.ServiceUnavailable)
    }

    @Test
    fun dedupe_malformedBody_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "not json", 200) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Retryable)
    }

    @Test
    fun dedupe_unexpectedStatusCode_mapsToRetryable() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "", 500) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Retryable)
    }

    @Test
    fun dedupe_networkError_mapsToRetryable() = runBlocking {
        val callFactory = ThrowingCallFactory(IOException("boom"))
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.dedupe("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is ContactDedupeResult.Retryable)
        assertEquals("boom", (result as ContactDedupeResult.Retryable).message)
    }

    @Test
    fun dedupe_sendsEmptyPostBody() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, """{"mergedCount": 0, "groups": []}""", 200) }
        val client = ContactSyncClient(callFactory = callFactory)

        client.dedupe("https://relay.example.com", "device-1", "secret-1")

        val body = callFactory.requests.single().body
        assertEquals(0L, body?.contentLength())
    }

    @Test
    fun pull_200_sendsPairingHeaders_notQueryParams() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "{}", 200) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1", since = 0L)

        assertTrue(result is ContactSyncResult.Success)
        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("device"))
        assertNull(sentRequest.url.queryParameter("secret"))
        assertEquals("0", sentRequest.url.queryParameter("since"))
    }

    @Test
    fun push_200_sendsPairingHeaders_notQueryParams() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "{}", 200) }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.push("https://relay.example.com", "device-1", "secret-1", baseCursor = 0L, changes = emptyList())

        assertTrue(result is ContactSyncResult.Success)
        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("device"))
        assertNull(sentRequest.url.queryParameter("secret"))
        assertEquals("POST", sentRequest.method)
    }

    /** 413 is "too many changes": retrying the same request can never succeed, so it must not
     *  look Retryable. The repository splits a BadRequest batch instead. */
    @Test
    fun push_413_mapsToBadRequest() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"error":"too many changes in one request","maxChanges":500}""", 413)
        }
        val client = ContactSyncClient(callFactory = callFactory)

        val result = client.push("https://relay.example.com", "device-1", "secret-1", baseCursor = 0L, changes = emptyList())

        assertTrue("got $result", result is ContactSyncResult.BadRequest)
    }
}
