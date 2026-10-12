package org.kysecurity.mail.contacts

import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.HEADER_DEVICE_ID
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.Assert.assertNull
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/** Named distinctly from [ContactSyncClientTest]'s fakes: same package, so JVM names collide. */
private class GroupsFakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return GroupsFakeCall(request, responder(request))
    }
}

private class GroupsThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = GroupsThrowingCall(request, exception)
}

private class GroupsFakeCall(private val req: Request, private val response: Response) : Call {
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
    override fun clone(): Call = GroupsFakeCall(req, response)
}

private class GroupsThrowingCall(private val req: Request, private val exception: Exception) : Call {
    override fun request(): Request = req
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = GroupsThrowingCall(req, exception)
}

private fun groupsResponse(request: Request, body: String, code: Int, message: String = "OK"): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message(message)
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class GroupsSyncClientTest {

    /** A reply without the list is not "the user has no groups": the refresh that follows would
     *  delete every group on the phone. Only an explicit empty list means none. */
    @Test
    fun pull_200_withoutAGroupsList_isNotASnapshot() = runBlocking {
        val missing = GroupsSyncClient(callFactory = GroupsFakeCallFactory { groupsResponse(it, "{}", 200) })
            .pull("https://relay.example.com/", "device-1", "secret-1")
        val empty = GroupsSyncClient(callFactory = GroupsFakeCallFactory { groupsResponse(it, """{"groups":[]}""", 200) })
            .pull("https://relay.example.com/", "device-1", "secret-1")

        assertTrue("got $missing", missing is GroupsSyncResult.Retryable)
        assertEquals(GroupsSyncResult.Success(emptyList()), empty)
    }

    @Test
    fun pull_200_decodesGroupsAndSendsExpectedRequest() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request ->
            groupsResponse(
                request,
                """{"groups": [{"id": "group-1", "name": "Work", "rev": 3, "createdAt": "2026-01-01T00:00:00Z", "updatedAt": "2026-01-02T00:00:00Z"}]}""",
                200,
            )
        }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com/", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Success)
        val groups = (result as GroupsSyncResult.Success).groups
        assertEquals(
            listOf(
                GroupDto(id = "group-1", name = "Work", rev = 3, createdAt = "2026-01-01T00:00:00Z", updatedAt = "2026-01-02T00:00:00Z"),
            ),
            groups,
        )

        val sentRequest = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/groups", sentRequest.url.newBuilder().query(null).build().toString())
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("device"))
        assertNull(sentRequest.url.queryParameter("secret"))
        assertEquals("GET", sentRequest.method)
    }

    @Test
    fun pull_200_emptyGroups_isStillSuccess() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, """{"groups": []}""", 200) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Success)
        assertEquals(emptyList<GroupDto>(), (result as GroupsSyncResult.Success).groups)
    }

    @Test
    fun pull_400_mapsToBadRequest() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, "bad params", 400) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.BadRequest)
        assertEquals("bad params", (result as GroupsSyncResult.BadRequest).message)
    }

    @Test
    fun pull_401_mapsToUnauthorized() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, "", 401) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Unauthorized)
    }

    @Test
    fun pull_503_mapsToServiceUnavailable() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, "", 503) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.ServiceUnavailable)
    }

    @Test
    fun pull_malformedBody_mapsToRetryable() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, "not json", 200) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Retryable)
    }

    @Test
    fun pull_unexpectedStatusCode_mapsToRetryable() = runBlocking {
        val callFactory = GroupsFakeCallFactory { request -> groupsResponse(request, "", 500) }
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Retryable)
    }

    @Test
    fun pull_networkError_mapsToRetryable() = runBlocking {
        val callFactory = GroupsThrowingCallFactory(IOException("boom"))
        val client = GroupsSyncClient(callFactory = callFactory)

        val result = client.pull("https://relay.example.com", "device-1", "secret-1")

        assertTrue(result is GroupsSyncResult.Retryable)
        assertEquals("boom", (result as GroupsSyncResult.Retryable).message)
    }
}
