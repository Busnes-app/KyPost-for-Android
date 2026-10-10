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

    /** Runs once, after a push is applied and before its reply: an edit made mid-sync. */
    var duringPush: (() -> Unit)? = null

    /** Every request, as "POST" or "GET since=N". */
    val requests = mutableListOf<String>()

    /** Cursors below this answer tooOld, as after tombstone GC. */
    var gcHighWater = 0L

    fun live(): List<ContactDto> = contacts.values.filterNot { it.deleted }

    /** Seeds server-side contacts, as if written by another client. */
    fun seed(vararg seeded: ContactDto) = seeded.forEach(::apply)

    /** Drops a contact with no tombstone, as after tombstone GC. */
    fun forget(uid: String) {
        contacts.remove(uid)
    }

    override fun newCall(request: Request): Call {
        val since: Long
        if (request.method == "POST") {
            requests += "POST"
            val buffer = Buffer().also { request.body!!.writeTo(it) }
            if (buffer.size > MAX_BODY_BYTES) return reply(request, 400, "invalid request")
            val push = json.decodeFromString(ContactSyncPushRequestDto.serializer(), buffer.readUtf8())
            if (push.changes.size > MAX_CHANGES) {
                return reply(request, 413, """{"error":"too many changes in one request","maxChanges":$MAX_CHANGES}""")
            }
            pushes += push
            push.changes.forEach(::apply)
            since = push.baseCursor
            duringPush?.also { duringPush = null }?.invoke()
        } else {
            since = request.url.queryParameter("since")?.toLong() ?: 0L
            requests += "GET since=$since"
        }
        if (loseNextResponse) {
            loseNextResponse = false
            return FakeServerCall(request, null)
        }
        val tooOld = since in 1 until gcHighWater
        val all = if (tooOld) emptyList() else contacts.values.filter { it.rev > since }
        val body = json.encodeToString(
            ContactSyncPullResponseDto.serializer(),
            ContactSyncPullResponseDto(
                cursor = seq,
                tooOld = tooOld,
                changed = all.filterNot { it.deleted },
                deleted = all.filter { it.deleted },
            ),
        )
        return reply(request, 200, body)
    }

    private fun reply(request: Request, code: Int, body: String): Call = FakeServerCall(
        request,
        Response.Builder().request(request).protocol(Protocol.HTTP_1_1).code(code).message("")
            .body(body.toResponseBody("application/json".toMediaType())).build(),
    )

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

    private companion object {
        const val MAX_CHANGES = 500
        const val MAX_BODY_BYTES = 1L shl 20
    }
}

internal val TEST_PAIRING = org.kysecurity.mail.push.PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "https://relay.example.com/register",
    pairingToken = "token-1",
    deviceId = "device-1",
    deviceSecret = "secret-1",
    pairedAtEpochMs = 0L,
)

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
