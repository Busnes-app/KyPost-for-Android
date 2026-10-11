package org.kysecurity.mail.contacts

import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Buffer
import okio.Timeout
import java.io.IOException
import java.util.UUID

/** `/api/contacts/sync` as kypost-server's `ApplyBatch` + `ChangedSince` behave: a blank uid
 *  mints one, an unknown uid is a create under that uid, a delete tombstones, and the reply is
 *  everything after the caller's cursor. */
internal class FakeContactServer : Call.Factory {
    private val json = Json { ignoreUnknownKeys = true }
    private val contacts = LinkedHashMap<String, ContactDto>()
    private var seq = 0L
    val pushes = mutableListOf<ContactSyncPushRequestDto>()

    /** Applies the next push, then fails the call as if the app died before reading the reply. */
    var loseNextResponse = false

    fun live(): List<ContactDto> = contacts.values.filterNot { it.deleted }

    override fun newCall(request: Request): Call {
        val since: Long
        if (request.method == "POST") {
            val buffer = Buffer().also { request.body!!.writeTo(it) }
            val push = json.decodeFromString(ContactSyncPushRequestDto.serializer(), buffer.readUtf8())
            pushes += push
            push.changes.forEach(::apply)
            since = push.baseCursor
        } else {
            since = request.url.queryParameter("since")?.toLong() ?: 0L
        }
        if (loseNextResponse) {
            loseNextResponse = false
            return FakeServerCall(request, null)
        }
        val all = contacts.values.filter { it.rev > since }
        val body = json.encodeToString(
            ContactSyncPullResponseDto.serializer(),
            ContactSyncPullResponseDto(
                cursor = seq,
                changed = all.filterNot { it.deleted },
                deleted = all.filter { it.deleted },
            ),
        )
        return FakeServerCall(
            request,
            Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body(body.toResponseBody("application/json".toMediaType())).build(),
        )
    }

    private fun apply(change: ContactDto) {
        val uid = change.uid.trim()
        if (change.deleted) {
            contacts[uid]?.let { contacts[uid] = ContactDto(uid = uid, rev = ++seq, deleted = true) }
            return
        }
        if (change.fn.isBlank()) return
        val key = uid.ifEmpty { UUID.randomUUID().toString() }
        contacts[key] = change.copy(uid = key, rev = ++seq, deleted = false)
    }
}

private class FakeServerCall(private val req: Request, private val response: Response?) : Call {
    private var executed = false
    override fun request(): Request = req
    override fun execute(): Response {
        executed = true
        return response ?: throw IOException("connection reset after the server committed")
    }
    override fun enqueue(responseCallback: Callback) = throw UnsupportedOperationException()
    override fun cancel() = Unit
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = false
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = FakeServerCall(req, response)
}
