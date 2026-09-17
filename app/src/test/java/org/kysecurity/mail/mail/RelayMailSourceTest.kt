package org.kysecurity.mail.mail

import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.pgp.OUTER_PLACEHOLDER_SUBJECT
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.testing.streamingResponse
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

private fun testPairing() = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = "device-1",
    deviceSecret = "secret-1",
    pairedAtEpochMs = 0L,
)

/** In-memory fake matching this repo's hand-rolled-fake test style (no mocking framework).
 *
 *  [RelayMailSource] only ever *reads* the checkpoint (to build `since`); advancing it is
 *  MailRepository's job, after Room is durable. The write counters exist to keep it that way. */
private class FakeMailCursorProvider(
    var storedCursor: String? = null,
    var forceDue: Boolean = false,
) : MailCursorProvider {
    var savedCursor: String? = null
        private set
    var fullResyncRecorded = false
        private set

    override fun cursor(subscriberId: String, folder: String): String? = storedCursor
    override fun saveCursor(subscriberId: String, folder: String, cursor: String) {
        savedCursor = cursor
        storedCursor = cursor
    }
    override fun shouldForceFullResync(subscriberId: String, folder: String): Boolean = forceDue
    override fun recordFullResync(subscriberId: String, folder: String) {
        fullResyncRecorded = true
    }
}

private fun MailOutcome<MailFetchResult>.checkpoint(): MailCheckpoint =
    requireNotNull((this as MailOutcome.Success).value.checkpoint) { "fetchInbox must report a checkpoint" }

/** Fakes OkHttp's [Call.Factory] so RelayMailSource can be exercised without a real network call
 *  or a MockWebServer dependency — this repo has neither and prefers hand-rolled fakes. */
private class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

/** Records request bodies as well as requests — [FakeCallFactory] keeps only the latter, and the
 *  PGP send flags are body fields. Mirrors MfaResponseClientTest's body-capturing fake. */
private class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val bodies = mutableListOf<String>()
    val urls = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        val buffer = okio.Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        urls.add(request.url.toString())
        return FakeCall(request, responder(request))
    }
}

/** A [Call.Factory] whose call always fails with [exception] — used to verify RelayMailSource's
 *  exception-to-[MailOutcome] mapping (e.g. a TLS pin mismatch) without a real network/TLS stack. */
private class ThrowingCallFactory(private val exception: Throwable) : Call.Factory {
    override fun newCall(request: Request): Call = object : Call {
        override fun request(): Request = request
        override fun execute(): Response = throw exception
        override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, java.io.IOException(exception))
        override fun cancel() {}
        override fun isExecuted(): Boolean = false
        override fun isCanceled(): Boolean = false
        override fun timeout(): Timeout = Timeout.NONE
        override fun clone(): Call = this
    }
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

private fun jsonResponse(request: Request, body: String, code: Int = 200): Response = Response.Builder()
    .request(request)
    .protocol(Protocol.HTTP_1_1)
    .code(code)
    .message("OK")
    .body(body.toResponseBody("application/json".toMediaType()))
    .build()

class RelayMailSourceTest {

    @Test
    fun freshPairing_noPersistedCursor_sendsSinceZero() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue(outcome is MailOutcome.Success)
        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertEquals("c1", outcome.checkpoint().cursor)
        assertEquals("sub-1", outcome.checkpoint().subscriberId)
    }

    /** The list rows render no bodies; only the opened message does, and it fetches its own from
     *  /api/mail/body. Measured against this client's own request shape (limit=50, since= always
     *  present, gzip): a since=0 window costs 151.4 KiB with bodies and 571 B without, and a poll
     *  carrying five new messages costs 15.9 KiB against 295 B. */
    @Test
    fun inboxRequest_optsOutOfMessageBodies() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(storedCursor = null),
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50)

        assertEquals("0", callFactory.requests.single().url.queryParameter("bodies"))
    }

    @Test
    fun fetchMessageBody_addressesOneMessageByMailboxAndId() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"body": "<p>hi</p>", "bodyMode": "html"}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.fetchMessageBody("42", "Archive")

        val url = callFactory.requests.single().url
        assertEquals("/api/mail/body", url.encodedPath)
        assertEquals("42", url.queryParameter("messageId"))
        assertEquals("Archive", url.queryParameter("mailbox"))
    }

    @Test
    fun fetchMessageBody_carriesThisDevicesCredentials() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"body": "hi", "bodyMode": "plain"}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.fetchMessageBody("42", "INBOX")

        val request = callFactory.requests.single()
        assertEquals("device-1", request.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", request.header(HEADER_DEVICE_SECRET))
    }

    /** bodyMode travels with the body and is never sniffed from the text: a plain-text message
     *  containing an RFC 5322 address literal like <user@example.com> parses as an unknown tag and
     *  the address disappears from what the user is shown. The server knows from the MIME parse. */
    @Test
    fun fetchMessageBody_carriesTheServersBodyModeVerbatim() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"body": "mail <user@example.com> now", "bodyMode": "plain"}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val body = (source.fetchMessageBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals("mail <user@example.com> now", body.html)
        assertEquals("plain", body.bodyMode)
    }

    /** The endpoint carries body and bodyMode and nothing else; recipients live only in the Room
     *  row, and MailRepository merges them back. Empty here, never a fabricated single address. */
    @Test
    fun fetchMessageBody_reportsNoRecipientsRatherThanGuessingThem() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"body": "hi", "bodyMode": "plain"}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val body = (source.fetchMessageBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals(emptyList<String>(), body.toAddresses)
        assertEquals(emptyList<String>(), body.ccAddresses)
    }

    /** The request arrived and the server answered definitively. Wording it as a network problem
     *  sends the user to check their signal over a message that will never open. */
    @Test
    fun fetchMessageBody_missingMessageIsNotWordedAsAConnectivityFailure() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "message not found", code = 404) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchMessageBody("42", "INBOX")

        assertFalse(outcome is MailOutcome.UpstreamFailure)
        assertFalse(outcome.userFacingMessage().orEmpty().contains("Couldn't reach"))
    }

    /** Same rule for a message too large for the server to hold in memory: a definite answer, and
     *  the 413 body is JSON, which must not reach a toast raw. */
    @Test
    fun fetchMessageBody_oversizeMessageIsNotWordedAsAConnectivityFailure() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"error": "message exceeds the maximum size"}""", code = 413)
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchMessageBody("42", "INBOX")

        assertFalse(outcome is MailOutcome.UpstreamFailure)
        val shown = outcome.userFacingMessage().orEmpty()
        assertFalse(shown.contains("Couldn't reach"))
        assertFalse(shown.contains("{"))
    }

    /** 502 IS the upstream failure the generic wording exists for — IMAP is down, retrying works. */
    @Test
    fun fetchMessageBody_imapFailureStaysAnUpstreamFailure() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "failed to fetch message", code = 502) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        assertTrue(source.fetchMessageBody("42", "INBOX") is MailOutcome.UpstreamFailure)
    }

    @Test
    fun sinceZeroResponse_isFlaggedAsAFullWindow() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertTrue((outcome as MailOutcome.Success).value.isFullWindow)
    }

    @Test
    fun cursorResponse_isNotFlaggedAsAFullWindow() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-42")
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-43", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertEquals(false, (outcome as MailOutcome.Success).value.isFullWindow)
    }

    /** Advancing the checkpoint here would acknowledge mail that has not reached Room yet; the
     *  relay would then never resend it. MailRepository commits it after reconciliation instead. */
    @Test
    fun fetchInbox_reportsTheCheckpointWithoutPersistingIt() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null, forceDue = true)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertEquals("c1", outcome.checkpoint().cursor)
        assertTrue(outcome.checkpoint().wasFullResync)
        assertNull("the source must not write the cursor", cursorProvider.savedCursor)
        assertFalse("the source must not stamp the full resync", cursorProvider.fullResyncRecorded)
    }

    @Test
    fun subsequentPoll_sendsPersistedCursor() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-42")
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-43", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertEquals("cursor-42", callFactory.requests.single().url.queryParameter("since"))
        assertEquals("cursor-43", outcome.checkpoint().cursor)
    }

    @Test
    fun deltaPoll_parsesNewUpdatedAndRemoved() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-1")
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {
                "Work": [
                  {"messageId": "m1", "sender": "a@example.com", "subject": "New", "body": "Full body", "label": "Work", "status": "unread", "changeType": "new"},
                  {"messageId": "m2", "sender": "b@example.com", "subject": "Updated", "label": "Work", "status": "read", "changeType": "updated"}
                ]
              },
              "cursor": "cursor-2",
              "delta": true,
              "removed": ["m3"]
            }
        """.trimIndent()
        val callFactory = FakeCallFactory { request -> jsonResponse(request, body) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        val result = (outcome as MailOutcome.Success).value
        assertTrue(result.isDelta)
        assertEquals(setOf("m2"), result.updatedMessageIds)
        assertEquals(listOf("m3"), result.removedMessageIds)
        assertEquals(2, result.messages.size)
        assertNull(result.messages.first { it.id == "m2" }.body)
        assertEquals("Full body", result.messages.first { it.id == "m1" }.body)
        assertEquals("cursor-2", outcome.checkpoint().cursor)
    }

    /** Encrypted rows can arrive without bodies while preserving the relay's delta classification. */
    @Test
    fun deltaPoll_keepsEncryptedRowsFlagsWithoutBodies() {
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {"Work": [
                {"messageId": "e1", "sender": "a@example.com", "subject": "New", "label": "Work",
                 "status": "unread", "changeType": "new", "pgpEncrypted": true, "pgpSigned": true},
                {"messageId": "e2", "sender": "b@example.com", "subject": "Updated", "label": "Work",
                 "status": "read", "changeType": "updated", "pgpEncrypted": true, "pgpSigned": true}
              ]},
              "cursor": "cursor-2", "delta": true, "removed": []
            }
        """.trimIndent()
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-1"),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val result = (source.fetchInbox("INBOX", 50) as MailOutcome.Success).value

        assertEquals(setOf("e2"), result.updatedMessageIds)
        assertEquals(setOf("e1", "e2"), result.messages.map { it.id }.toSet())
        result.messages.forEach { row ->
            assertTrue(row.pgpEncrypted)
            assertTrue(row.pgpSigned)
            assertNull(row.body)
        }
    }

    @Test
    fun explicitForceFullResync_sendsSinceZero_regardlessOfPersistedCursor() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-99")
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-100", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50, forceFullResync = true)

        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertTrue(outcome.checkpoint().wasFullResync)
    }

    @Test
    fun cadenceDue_sendsSinceZero_evenWithoutExplicitForce() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = "cursor-5", forceDue = true)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "cursor-6", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertEquals("0", callFactory.requests.single().url.queryParameter("since"))
        assertTrue(outcome.checkpoint().wasFullResync)
    }

    @Test
    fun nonDeltaLegacyResponse_stillParsesAsFullSnapshot() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val body = """
            {
              "tabs": ["Work"],
              "byTab": {"Work": [{"messageId": "m1", "sender": "a@example.com", "subject": "S", "body": "B", "label": "Work", "status": "unread"}]}
            }
        """.trimIndent()
        val callFactory = FakeCallFactory { request -> jsonResponse(request, body) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        val result = (outcome as MailOutcome.Success).value
        assertTrue(!result.isDelta)
        assertEquals(1, result.messages.size)
        assertEquals("", outcome.checkpoint().cursor)
    }

    @Test
    fun fetchInbox_sendsPairingHeaders_notQueryParams() {
        val cursorProvider = FakeMailCursorProvider(storedCursor = null)
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"tabs": [], "byTab": {}, "cursor": "c1", "delta": true, "removed": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = cursorProvider,
            callFactory = callFactory,
        )

        source.fetchInbox("INBOX", 50)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun listFolders_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request ->
            jsonResponse(request, """{"parent": null, "folders": []}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.listFolders(null)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun createFolder_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "", code = 200) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.createFolder("INBOX", "New Folder")

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun deleteFolder_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request -> jsonResponse(request, "", code = 200) }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.deleteFolder("INBOX/Old")

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
        assertEquals("INBOX/Old", sentRequest.url.queryParameter("folder"))
    }

    @Test
    fun downloadAttachment_sendsPairingHeaders_notQueryParams() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .header("Content-Disposition", "attachment; filename=\"file.pdf\"")
                .header("Content-Type", "application/pdf")
                .body("bytes".toResponseBody("application/pdf".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.downloadAttachment("m1", "INBOX", 0)

        val sentRequest = callFactory.requests.single()
        assertEquals("device-1", sentRequest.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sentRequest.header(HEADER_DEVICE_SECRET))
        assertNull(sentRequest.url.queryParameter("sub"))
        assertNull(sentRequest.url.queryParameter("hash"))
    }

    @Test
    fun downloadAttachment_readsBodiesLargerThanOneOkioSegment() {
        // Deliberately not a round multiple of 8192, so a truncation to any segment boundary shows.
        val payload = ByteArray(200_000) { (it % 251).toByte() }
        val callFactory = FakeCallFactory { request ->
            streamingResponse(
                request,
                payload,
                contentType = "application/pdf",
                headers = mapOf(
                    "Content-Disposition" to "attachment; filename=\"big.pdf\"",
                    "Content-Type" to "application/pdf",
                ),
            )
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.downloadAttachment("m1", "INBOX", 0)

        assertTrue("expected Success, got $outcome", outcome is MailOutcome.Success)
        val downloaded = (outcome as MailOutcome.Success).value
        assertEquals(payload.size, downloaded.bytes.size)
        assertTrue("attachment bytes were altered in transit", payload.contentEquals(downloaded.bytes))
        assertEquals("big.pdf", downloaded.name)
    }

    /** A small limit stands in for the real 25 MB bound; bodies read one segment at a time. */
    private fun readBoundedFrom(bytes: ByteArray, limit: Long): ByteArray {
        val body = streamingResponse(Request.Builder().url("https://relay.example.com/a").build(), bytes).body!!
        return readBounded(body, limit)
    }

    @Test
    fun readBounded_throwsRatherThanTruncatingAnOversizedBody() {
        val oversized = ByteArray(10_001) { (it % 251).toByte() }
        try {
            readBoundedFrom(oversized, 10_000L)
            fail("expected an IOException for a body past the limit")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message.orEmpty().contains("larger than"))
        }
    }

    /** The declared length now refuses the body before a byte is read, rather than reading `limit`
     *  of them and then discovering there was more. */
    @Test
    fun readBounded_refusesAnOversizedBodyWithoutReadingIt() {
        val oversized = ByteArray(10_001) { (it % 251).toByte() }
        val response = streamingResponse(
            Request.Builder().url("https://relay.example.com/a").build(),
            oversized,
        )
        try {
            readBounded(response.body!!, 10_000L)
            fail("expected an IOException for a body past the limit")
        } catch (expected: java.io.IOException) {
            assertTrue(expected.message.orEmpty().contains("declared"))
        }
    }

    @Test
    fun readBounded_acceptsABodyExactlyAtTheLimit() {
        // The boundary the truncation check must not over-reject: a body of exactly the limit is
        // legitimate, and `exhausted()` has to report end-of-stream rather than "more to come".
        val exact = ByteArray(10_000) { (it % 251).toByte() }
        assertTrue(exact.contentEquals(readBoundedFrom(exact, 10_000L)))
    }

    @Test
    fun readBounded_readsAMultiSegmentBodyUnderTheLimitWhole() {
        // Not a round multiple of 8192, so a truncation to any Okio segment boundary shows.
        val payload = ByteArray(200_000) { (it % 251).toByte() }
        assertTrue(payload.contentEquals(readBoundedFrom(payload, 25L * 1024 * 1024)))
    }

    @Test
    fun relayRequests_refuseAPersistedNonHttpsServerUrl() {
        // A pairing saved before the https gate existed; its requests carry X-Kypost-Device-Secret.
        var called = false
        val callFactory = FakeCallFactory { request ->
            called = true
            streamingResponse(request, ByteArray(0))
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing().copy(serverUrl = "http://relay.example") },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50, forceFullResync = false)

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
        assertFalse("the request must never reach the network", called)
    }

    @Test
    fun tlsPinMismatch_mapsToCertificateMismatch_notGenericNetworkError() {
        val callFactory = ThrowingCallFactory(javax.net.ssl.SSLPeerUnverifiedException("pin mismatch"))
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue(outcome is MailOutcome.CertificateMismatch)
        assertEquals("pin mismatch", (outcome as MailOutcome.CertificateMismatch).message)
    }

    @Test
    fun tlsPinMismatch_onDownloadAttachment_alsoMapsToCertificateMismatch() {
        val callFactory = ThrowingCallFactory(javax.net.ssl.SSLPeerUnverifiedException("pin mismatch"))
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.downloadAttachment("m1", "INBOX", 0)

        assertTrue(outcome is MailOutcome.CertificateMismatch)
    }

    @Test
    fun send409WithClientSideNeeded_mapsToClientSideNeeded() {
        val body = """{"error":"this account's PGP key is end-to-end protected, so the server cannot sign or encrypt on your behalf","clientSideNeeded":true}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected ClientSideNeeded, got $outcome", outcome is MailOutcome.ClientSideNeeded)
    }

    @Test
    fun send409WithoutMarker_staysBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, """{"error":"conflict"}""", code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
    }

    /** The keyless-recipient refusal. Nothing was delivered — the 409 happens before any SMTP —
     *  so re-sending with allowPickupFallback cannot duplicate the message. */
    @Test
    fun send409WithKeylessRecipients_mapsToPickupFallbackNeeded() {
        val body = """{"error":"some recipients have no usable PGP key","keylessRecipients":["carol@example.com"],"pickupFallbackAvailable":true}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "carol@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected PickupFallbackNeeded, got $outcome", outcome is MailOutcome.PickupFallbackNeeded)
        assertEquals(
            listOf("carol@example.com"),
            (outcome as MailOutcome.PickupFallbackNeeded).keylessRecipients,
        )
    }

    @Test
    fun send409WithBothMarkers_prefersClientSideNeeded() {
        val body = """{"error":"e2e","clientSideNeeded":true,"keylessRecipients":["carol@example.com"]}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "carol@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected ClientSideNeeded, got $outcome", outcome is MailOutcome.ClientSideNeeded)
    }

    @Test
    fun send409WithNeitherField_isGenericBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, """{"error":"conflict"}""", code = 409) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
        assertTrue(
            "raw JSON must not reach the user: $outcome",
            !(outcome as MailOutcome.BadRequest).message.contains("{"),
        )
    }

    @Test
    fun send409WithEmptyKeylessList_isGenericBadRequest() {
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory {
                request -> jsonResponse(request, """{"error":"x","keylessRecipients":[]}""", code = 409)
            },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertTrue("expected BadRequest, got $outcome", outcome is MailOutcome.BadRequest)
    }

    @Test
    fun send502_carriesTheServersPlainTextReason() {
        val reason = "failed to deliver a pickup link to any recipient; nothing was sent"
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, reason, code = 502) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        assertEquals(reason, (outcome as MailOutcome.UpstreamFailure).message)
    }

    @Test
    fun resendWithFallback_differsOnlyInAllowPickupFallback() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )
        val draft = MailDraft(
            to = "carol@example.com", cc = "bob@example.com", subject = "hi", body = "<p>hello</p>",
            mode = "html", encrypt = true, sign = true,
        )

        source.sendMail(draft)
        source.sendMail(draft.copy(allowPickupFallback = true))

        // Compared structurally, not as strings: kotlinx.serialization's encodeDefaults is false,
        // so the refused attempt omits allowPickupFallback entirely rather than sending false.
        val wireJson = Json { ignoreUnknownKeys = true }
        val first = wireJson.decodeFromString<RelayMailRequestDto>(callFactory.bodies[0])
        val second = wireJson.decodeFromString<RelayMailRequestDto>(callFactory.bodies[1])
        assertEquals(false, first.allowPickupFallback)
        assertEquals(true, second.allowPickupFallback)
        assertEquals(first, second.copy(allowPickupFallback = false))
    }

    @Test
    fun send200WithWarning_isSuccessCarryingTheWarning() {
        val body = """{"ok":true,"sentSaved":false,"warning":"failed to deliver a pickup link to 1 of 3 recipient(s)"}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val outcome = source.sendMail(
            MailDraft(to = "a@example.com", subject = "s", body = "b", encrypt = true),
        )

        val sent = (outcome as MailOutcome.Success).value
        assertEquals("failed to deliver a pickup link to 1 of 3 recipient(s)", sent.warning)
        assertEquals(false, sent.sentSaved)
    }

    @Test
    fun rateLimit429_carriesRetryAfterSeconds() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "120")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertEquals(120L, (outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    @Test
    fun rateLimit429_withoutUsableRetryAfter_hasNullDelay() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertNull((outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    @Test
    fun rateLimit429_onDownloadAttachment_alsoMapsToRateLimited() {
        val callFactory = FakeCallFactory { request ->
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(429)
                .message("Too Many Requests")
                .header("Retry-After", "30")
                .body("too many requests".toResponseBody("text/plain".toMediaType()))
                .build()
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        val outcome = source.downloadAttachment("m1", "INBOX", 0)

        assertTrue("expected RateLimited, got $outcome", outcome is MailOutcome.RateLimited)
        assertEquals(30L, (outcome as MailOutcome.RateLimited).retryAfterSeconds)
    }

    @Test
    fun inboxResponse_carriesPgpFieldsThroughToUiEmail() {
        val body = """
            {"tabs":["Inbox"],"byTab":{"Inbox":[
              {"messageId":"1","sender":"a@example.com","subject":"[Encrypted] Email Sent by KyPost",
               "pgpEncrypted":true,"pgpSigned":true,"pgpVerified":true,"pgpSignerFingerprint":"ABCD"},
              {"messageId":"2","sender":"b@example.com","subject":"plain"}
            ]},"cursor":"7"}
        """.trimIndent()
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val outcome = source.fetchInbox("INBOX", 50)

        assertTrue("expected Success, got $outcome", outcome is MailOutcome.Success)
        val messages = (outcome as MailOutcome.Success).value.messages
        val encrypted = messages.first { it.id == "1" }
        assertTrue(encrypted.pgpEncrypted)
        assertTrue(encrypted.pgpSigned)
        assertTrue(encrypted.pgpVerified)
        assertEquals("ABCD", encrypted.pgpSignerFingerprint)
        assertEquals("", encrypted.pgpDecryptError)
        // Absent fields are omitempty server-side, so their defaults are the contract for
        // ordinary mail — not an unknown state.
        val plain = messages.first { it.id == "2" }
        assertEquals(false, plain.pgpEncrypted)
        assertEquals("", plain.pgpSignerFingerprint)
    }

    @Test
    fun sendMail_putsPgpFlagsOnTheWire() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.sendMail(
            MailDraft(
                to = "bob@example.com", subject = "hi", body = "hello",
                sign = true, encrypt = true, allowPickupFallback = true,
            ),
        )

        val sent = callFactory.bodies.single()
        assertTrue("expected sign in $sent", sent.contains("\"sign\":true"))
        assertTrue("expected encrypt in $sent", sent.contains("\"encrypt\":true"))
        assertTrue("expected allowPickupFallback in $sent", sent.contains("\"allowPickupFallback\":true"))
    }

    @Test
    fun encryptedDraft_postsOnlyRecipientAndCiphertext() {
        val calls = BodyRecordingCallFactory { request -> jsonResponse(request, """{"ok":true}""") }
        val source = RelayMailSource(
            pairingProvider = { testPairing() }, cursorProvider = FakeMailCursorProvider(), callFactory = calls,
        )
        val draft = ClientEncryptedDraft("alice@example.com", "encrypted MIME")
        assertTrue(source.saveClientEncryptedDraft(draft) is MailOutcome.Success)
        assertEquals("https://relay.example.com/api/mail/draft", calls.urls.single())
        val fields = Json.parseToJsonElement(calls.bodies.single()) as kotlinx.serialization.json.JsonObject
        assertEquals(setOf("to", "pgpDraft"), fields.keys)
        assertEquals(Json.parseToJsonElement("\"alice@example.com\""), fields["to"])
        assertEquals(Json.parseToJsonElement("\"encrypted MIME\""), fields["pgpDraft"])
        assertEquals("ClientEncryptedDraft(redacted)", draft.toString())
    }

    @Test
    fun encryptedDraftRejectsUnacknowledgedSuccessResponses() {
        for (body in listOf("{\"ok\":false}", "{}", "not JSON", "{\"ok\":\"true\"}")) {
            val calls = BodyRecordingCallFactory { request -> jsonResponse(request, body) }
            val source = RelayMailSource(
                pairingProvider = { testPairing() }, cursorProvider = FakeMailCursorProvider(), callFactory = calls,
            )
            assertTrue("unacknowledged 200 accepted: $body",
                source.saveClientEncryptedDraft(ClientEncryptedDraft("a@example.com", "MIME")) is MailOutcome.UpstreamFailure)
        }
    }

    @Test
    fun saveDraft_omitsPgpFlags() {
        val callFactory = BodyRecordingCallFactory { request -> jsonResponse(request, """{"ok":true}""") }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.saveDraft(
            MailDraft(to = "bob@example.com", subject = "hi", body = "hello", encrypt = true, sign = true),
        )

        val wireJson = Json { ignoreUnknownKeys = true }
        val sent = wireJson.decodeFromString<RelayMailRequestDto>(callFactory.bodies.single())
        assertEquals(false, sent.sign)
        assertEquals(false, sent.encrypt)
        assertEquals(false, sent.allowPickupFallback)
    }

    @Test
    fun sendClientEncrypted_postsCiphertextToTheSendPgpEndpoint() {
        val callFactory = BodyRecordingCallFactory { request ->
            jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""")
        }
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = callFactory,
        )

        source.sendClientEncrypted(
            ClientEncryptedMessage(
                from = "me@example.com",
                to = listOf("alice@example.com"),
                cc = emptyList(),
                bcc = listOf("carol@example.com"),
                deliveries = listOf(
                    ClientEncryptedDelivery(listOf("alice@example.com"), "MIME-A"),
                    ClientEncryptedDelivery(listOf("carol@example.com"), "MIME-B"),
                ),
                sentCopy = "MIME-SENT",
            ),
        )

        val wireJson = Json { ignoreUnknownKeys = true }
        val sent = wireJson.decodeFromString<RelayClientEncryptedRequestDto>(callFactory.bodies.single())
        assertEquals("https://relay.example.com/api/mail/send-pgp", callFactory.urls.single())
        assertEquals(2, sent.deliveries.size)
        assertEquals(listOf("carol@example.com"), sent.deliveries[1].recipients)
        assertEquals("MIME-SENT", sent.sentCopy)
        assertEquals(true, sent.sentCopyEncrypted)
        assertEquals(OUTER_PLACEHOLDER_SUBJECT, sent.subject)
    }

    private fun clientEncrypted(materialGeneration: Long? = null) = ClientEncryptedMessage(
        from = "me@example.com",
        to = listOf("alice@example.com"),
        cc = emptyList(),
        bcc = emptyList(),
        deliveries = listOf(ClientEncryptedDelivery(listOf("alice@example.com"), "MIME")),
        sentCopy = "SENT",
        materialGeneration = materialGeneration,
    )

    /** KyPost-Server #210: a converted account requires the generation; a legacy one must not see
     *  a made-up value, so the field is absent rather than zero. */
    @Test
    fun sendClientEncrypted_sendsTheMaterialGenerationOnlyWhenHeld() {
        val callFactory = BodyRecordingCallFactory { request -> jsonResponse(request, """{"ok":true,"sentSaved":true,"warning":""}""") }
        val source = RelayMailSource(pairingProvider = { testPairing() }, cursorProvider = FakeMailCursorProvider(), callFactory = callFactory)

        source.sendClientEncrypted(clientEncrypted(materialGeneration = 2L))
        source.sendClientEncrypted(clientEncrypted(materialGeneration = null))

        assertTrue(callFactory.bodies[0], callFactory.bodies[0].contains("\"materialGeneration\":2"))
        assertFalse(callFactory.bodies[1], callFactory.bodies[1].contains("materialGeneration"))
    }

    /** The account's keys moved on since this device enrolled. Only re-enrolling helps; the user
     *  is told that rather than "Conflicting request". */
    @Test
    fun sendClientEncrypted_409PgpStateChanged_tellsTheUserToEnrollAgain() {
        val body = """{"error":"the account's key material changed; reload and send again","pgpStateChanged":true,"materialGeneration":3}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendClientEncrypted(clientEncrypted(materialGeneration = 2L))

        assertEquals(MailOutcome.BadRequest(PGP_STATE_CHANGED_MESSAGE), outcome)
    }

    @Test
    fun sendClientEncrypted_409ReenrollmentRequired_tellsTheUserToEnrollAgain() {
        val body = """{"error":"this device holds retired key material; enroll it again before sending","reenrollmentRequired":true,"materialGeneration":2}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body, code = 409) },
        )

        val outcome = source.sendClientEncrypted(clientEncrypted(materialGeneration = 2L))

        assertEquals(MailOutcome.BadRequest(REENROLLMENT_REQUIRED_MESSAGE), outcome)
    }

    @Test
    fun sendClientEncrypted_200WithWarning_isSuccessCarryingIt() {
        val body = """{"ok":true,"sentSaved":false,"warning":"1 bcc delivery(s) failed"}"""
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, body) },
        )

        val outcome = source.sendClientEncrypted(
            ClientEncryptedMessage(
                from = "me@example.com",
                to = listOf("alice@example.com"),
                cc = emptyList(),
                bcc = emptyList(),
                deliveries = listOf(ClientEncryptedDelivery(listOf("alice@example.com"), "MIME")),
                sentCopy = "SENT",
            ),
        )

        val value = (outcome as MailOutcome.Success).value
        assertEquals("1 bcc delivery(s) failed", value.warning)
        assertEquals(false, value.sentSaved)
    }

    @Test
    fun forbidden_carriesTheServersProse() {
        val reason = "the from address is not a verified send-as alias for this account"
        val source = RelayMailSource(
            pairingProvider = { testPairing() },
            cursorProvider = FakeMailCursorProvider(),
            callFactory = FakeCallFactory { request -> jsonResponse(request, reason, code = 403) },
        )

        val outcome = source.sendMail(MailDraft(to = "a@example.com", subject = "s", body = "b"))

        assertEquals(reason, (outcome as MailOutcome.BadRequest).message)
    }
}
