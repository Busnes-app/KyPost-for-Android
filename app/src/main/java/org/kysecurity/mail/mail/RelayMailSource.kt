package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.executeDecoding
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.pgp.OUTER_PLACEHOLDER_SUBJECT
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.pairingUrlHost
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException

private val JSON_MEDIA_TYPE = "application/json".toMediaType()
private const val NOT_CONFIGURED_PREFIX = "imap configuration is required"
private const val FULL_RESYNC_SINCE = "0"
private const val CHANGE_TYPE_UPDATED = "updated"
private const val HEADER_RETRY_AFTER = "Retry-After"

/** The JSON field, not the error prose — the prose is user-facing copy and may be reworded. */
private const val CLIENT_SIDE_NEEDED_MARKER = "clientSideNeeded"

/** /api/mail/send-pgp on a converted account, KyPost-Server #210. Both mean the same thing to
 *  a device: what it holds is no longer the account's current material. */
private const val PGP_STATE_CHANGED_MARKER = "pgpStateChanged"
private const val REENROLLMENT_REQUIRED_MARKER = "reenrollmentRequired"
internal const val PGP_STATE_CHANGED_MESSAGE =
    "Your account's encryption keys changed since this device was set up. Enroll this device again in Security settings, then send again."
internal const val REENROLLMENT_REQUIRED_MESSAGE =
    "This device holds older encryption keys. Enroll it again in Security settings before sending."

/** Not a `data class`: the generated equals/hashCode would be identity-over-[ByteArray]. */
private class DownloadResponse(
    val code: Int,
    val bytes: ByteArray,
    val name: String,
    val contentType: String,
    val retryAfter: String?,
)

/** Retry-After is seconds or an HTTP date (RFC 9110); this server sends seconds
 *  (wkd_ratelimit.go, device_auth.go). A date form, a negative value, or garbage all yield null,
 *  which callers render as a generic "try again later" — never as "retry now". */
internal fun parseRetryAfterSeconds(header: String?): Long? =
    header?.trim()?.toLongOrNull()?.takeIf { it >= 0 }

class RelayMailSource(
    private val pairingProvider: () -> PairingData?,
    private val cursorProvider: MailCursorProvider,
    private val json: Json = Json { ignoreUnknownKeys = true },
    /** In production a pinned-or-refuse factory; never null-coalesce it against an unpinned one. */
    private val callFactory: Call.Factory,
) : MailSource {

    private fun effectiveCallFactory(): Call.Factory = callFactory

    /** Attaches this device's own pairing credentials. A missing deviceId/deviceSecret (not yet
     *  registered) sends blank headers, which the server rejects with 401 — surfaced through the
     *  same [mapErrorCode] path as any other bad credential, rather than a special-cased result. */
    private fun Request.Builder.authed(pairing: PairingData): Request.Builder =
        pairingAuthHeaders(pairing.deviceId.orEmpty(), pairing.deviceSecret.orEmpty())

    override fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean): MailOutcome<MailFetchResult> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val since = sinceValue(pairing.subscriberId, mailbox, forceFullResync)
        val url = base.newBuilder()
            .addQueryParameter("limit", limit.toString())
            .addQueryParameter("mailbox", mailbox)
            .addQueryParameter("since", since)
            // The list rows render no body; only the opened message does, and it fetches its own
            // from /api/mail/body. Opting out costs one round trip per first open and takes a
            // since=0 window from 151.4 KiB to 571 B, a five-new-message poll from 15.9 KiB to
            // 295 B, and ~2.6 MiB off the decoded peak (see MemoryBudget).
            .addQueryParameter("bodies", "0")
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        // Streamed, not `.string()` + decodeFromString: this is the largest JSON this app reads,
        // and materialising it as a UTF-16 String held a second copy alive beside the DTOs.
        return executeStreaming(request, RelayInboxResponseDto.serializer()) { code, parsed, errorBody ->
            if (code != 200) return@executeStreaming mapErrorCode(code, errorBody)
            if (parsed == null) return@executeStreaming MailOutcome.UpstreamFailure("Malformed inbox response")
            // The checkpoint is returned, not saved here: MailRepository commits it once the
            // messages it covers are in Room. See [MailCheckpoint].
            // changeType is the source of truth for new-vs-updated, never whether `since` was sent
            // (Mobile_Mail_Relay.md Part 5) — read it straight off each entry, not derived state.
            val entries = parsed.byTab.flatMap { (tab, emails) -> emails.map { it.toUiEmail(tab) to it.changeType } }
            MailOutcome.Success(
                MailFetchResult(
                    tabs = parsed.tabs,
                    messages = entries.map { it.first },
                    isDelta = parsed.delta,
                    updatedMessageIds = entries.filter { it.second == CHANGE_TYPE_UPDATED }.map { it.first.id }.toSet(),
                    removedMessageIds = parsed.removed,
                    isFullWindow = since == FULL_RESYNC_SINCE,
                    checkpoint = MailCheckpoint(
                        subscriberId = pairing.subscriberId,
                        cursor = parsed.cursor,
                        wasFullResync = since == FULL_RESYNC_SINCE,
                    ),
                ),
            )
        }
    }

    /** since=0 when forced (explicitly, or the daily self-heal cadence is due), or no cursor is
     *  persisted yet (fresh pairing) — otherwise the persisted cursor (Mobile_Mail_Relay.md Part 5). */
    private fun sinceValue(subscriberId: String, folder: String, forceFullResync: Boolean): String {
        val forced = forceFullResync || cursorProvider.shouldForceFullResync(subscriberId, folder)
        return if (forced) FULL_RESYNC_SINCE else cursorProvider.cursor(subscriberId, folder) ?: FULL_RESYNC_SINCE
    }

    override fun listFolders(parent: String?): MailOutcome<FolderListResult> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val urlBuilder = base.newBuilder()
        if (!parent.isNullOrBlank()) urlBuilder.addQueryParameter("parent", parent)
        val request = Request.Builder().url(urlBuilder.build()).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayFolderListResponseDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed folder list response")
            MailOutcome.Success(
                FolderListResult(parent = parsed.parent, folders = parsed.folders.map { FolderInfo(it.path, it.deletable) }),
            )
        }
    }

    override fun createFolder(parent: String, name: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(RelayFolderCreateRequestDto(parent = parent, name = name))
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun renameFolder(folder: String, name: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(RelayFolderRenameRequestDto(folder = folder, name = name))
        val request = Request.Builder().url(base).put(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun deleteFolder(folder: String): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/folders") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder().addQueryParameter("folder", folder).build()
        val request = Request.Builder().url(url).delete()
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String?,
    ): MailOutcome<MailActionOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/inbox/actions") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val requestDto = RelayActionRequestDto(
            action = action.wireValue(),
            messageIds = messageIds,
            mailbox = mailbox,
            targetMailbox = targetMailbox,
        )
        val body = json.encodeToString(requestDto)
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelayActionResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed action response")
            // ok:false with a non-empty failed[] is still a partial success — processed ids already
            // took effect (Mobile_Mail_Relay.md Part 2's explicit callout).
            MailOutcome.Success(
                MailActionOutcome(processed = parsed.processed, failed = parsed.failed.map { it.messageId to it.error }),
            )
        }
    }

    override fun saveDraft(draft: MailDraft): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/draft") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(draft.toWireDto())
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody -> mutationOutcome(code, rawBody) }
    }

    override fun saveClientEncryptedDraft(draft: ClientEncryptedDraft): MailOutcome<Unit> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/draft") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(RelayClientEncryptedDraftDto(draft.to, draft.pgpDraft))
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing).build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val reply = runCatching { json.parseToJsonElement(rawBody) as? JsonObject }.getOrNull()
            if (reply?.get("ok") == JsonPrimitive(true)) MailOutcome.Success(Unit)
            else MailOutcome.UpstreamFailure("Draft save was not acknowledged")
        }
    }

    override fun sendMail(draft: MailDraft): MailOutcome<MailSendOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/send") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(draft.toSendWireDto())
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelaySendResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed send response")
            MailOutcome.Success(MailSendOutcome(sentSaved = parsed.sentSaved, warning = parsed.warning))
        }
    }

    override fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/send-pgp")
            ?: return MailOutcome.BadRequest("Server URL is not valid")
        val body = json.encodeToString(
            RelayClientEncryptedRequestDto(
                from = message.from,
                subject = OUTER_PLACEHOLDER_SUBJECT,
                mode = message.mode,
                to = message.to,
                cc = message.cc,
                bcc = message.bcc,
                deliveries = message.deliveries.map {
                    RelayClientEncryptedDeliveryDto(recipients = it.recipients, ciphertext = it.ciphertext)
                },
                sentCopy = message.sentCopy,
                sentCopyEncrypted = true,
                materialGeneration = message.materialGeneration,
            ),
        )
        val request = Request.Builder().url(base).post(body.toRequestBody(JSON_MEDIA_TYPE))
            .authed(pairing)
            .build()
        return execute(request) { code, rawBody ->
            if (code != 200) return@execute mapErrorCode(code, rawBody)
            val parsed = runCatching { json.decodeFromString<RelaySendResponseDto>(rawBody) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed send response")
            MailOutcome.Success(MailSendOutcome(sentSaved = parsed.sentSaved, warning = parsed.warning))
        }
    }

    /** The counterpart to `bodies=0` on [fetchInbox]: the list carries no bodies, so the opened
     *  message fetches its own. Same mailbox+messageId pair the attachment endpoints take.
     *
     *  Recipients come back empty because the endpoint does not carry them; [MailRepository]
     *  merges `to`/`cc` from the cached row, which is their only source. */
    override fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/body") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", folder)
            .addQueryParameter("messageId", messageId)
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            // Handled here rather than in mapErrorCode, whose generic fallback words every unknown
            // status as an upstream failure — which userFacingMessage renders as "Couldn't reach
            // the mail server". Both of these ARRIVED and were answered definitively, and sending
            // the user to check their signal over a message that will never open is a lie. 502
            // still goes to the shared mapper, because that one really is retry-later.
            if (code == 404) {
                return@execute MailOutcome.BadRequest("This message is no longer on the server")
            }
            // Deliberately not the response body: the 413 is JSON, and raw JSON in a toast is
            // worse than a sentence — the same call mapErrorCode makes for an unrecognized 409.
            if (code == 413) {
                return@execute MailOutcome.BadRequest("This message is too large for the server to open")
            }
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayMessageBodyDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed message body response")
            MailOutcome.Success(
                MailMessageBody(
                    html = parsed.body,
                    bodyMode = parsed.bodyMode,
                    toAddresses = emptyList(),
                    ccAddresses = emptyList(),
                ),
            )
        }
    }

    override fun listAttachments(messageId: String, folder: String): MailOutcome<List<AttachmentInfo>> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/attachments") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", folder)
            .addQueryParameter("messageId", messageId)
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            .build()
        return execute(request) { code, body ->
            if (code != 200) return@execute mapErrorCode(code, body)
            val parsed = runCatching { json.decodeFromString<RelayAttachmentListResponseDto>(body) }.getOrNull()
                ?: return@execute MailOutcome.UpstreamFailure("Malformed attachment list response")
            MailOutcome.Success(parsed.attachments.map { AttachmentInfo(it.index, it.name, it.mimeType, it.size) })
        }
    }

    override fun downloadAttachment(messageId: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> {
        val pairing = pairingProvider() ?: return MailOutcome.Unauthorized("Device is not paired")
        val base = baseUrl(pairing, "/api/mail/attachment") ?: return MailOutcome.BadRequest("Server URL is not valid")
        val url = base.newBuilder()
            .addQueryParameter("mailbox", folder)
            .addQueryParameter("messageId", messageId)
            .addQueryParameter("index", index.toString())
            .build()
        val request = Request.Builder().url(url).get()
            .authed(pairing)
            // The one route allowed past the JSON-sized default; see [BodyLimit].
            .tag(org.kysecurity.mail.BodyLimit::class.java, org.kysecurity.mail.BodyLimit(MAX_ATTACHMENT_DOWNLOAD_BYTES))
            .build()
        // Binary response: read bytes and metadata headers inside the use block, not execute()'s
        // string() path.
        val result = effectiveCallFactory().executeSync(request) { response ->
            DownloadResponse(
                code = response.code,
                // Bounded read: `bytes()` would materialise whatever a relay chose to stream.
                bytes = response.body?.let { readBounded(it, MAX_ATTACHMENT_DOWNLOAD_BYTES) } ?: ByteArray(0),
                name = filenameFromDisposition(response.header("Content-Disposition")),
                contentType = response.header("Content-Type") ?: "application/octet-stream",
                retryAfter = response.header(HEADER_RETRY_AFTER),
            )
        }
        val downloadException = result.exceptionOrNull()
        if (downloadException is javax.net.ssl.SSLPeerUnverifiedException) {
            return MailOutcome.CertificateMismatch(downloadException.message ?: "Certificate pin mismatch")
        }
        val download = result.getOrNull()
            ?: return MailOutcome.UpstreamFailure(downloadException?.message ?: "Network error")
        val code = download.code
        val bytes = download.bytes
        val retryAfter = download.retryAfter
        if (code == 429) return rateLimited(bytes.toString(Charsets.UTF_8), retryAfter)
        if (code != 200) return mapErrorCode(code, bytes.toString(Charsets.UTF_8))
        return MailOutcome.Success(
            DownloadedAttachment(
                name = download.name.ifBlank { "attachment" },
                mimeType = download.contentType.substringBefore(';').trim(),
                bytes = bytes,
            ),
        )
    }

    private fun <T> rateLimited(rawBody: String, retryAfter: String?): MailOutcome<T> =
        MailOutcome.RateLimited(
            message = rawBody.ifBlank { "Too many requests" },
            retryAfterSeconds = parseRetryAfterSeconds(retryAfter),
        )

    private fun mutationOutcome(code: Int, rawBody: String): MailOutcome<Unit> =
        if (code == 200) MailOutcome.Success(Unit) else mapErrorCode(code, rawBody)

    // 429 is deliberately absent here: it needs the Retry-After header, which this signature
    // can't see, so it is short-circuited in [execute] and [downloadAttachment] instead.
    private fun <T> mapErrorCode(code: Int, rawBody: String): MailOutcome<T> = when (code) {
        400 -> if (rawBody.contains(NOT_CONFIGURED_PREFIX, ignoreCase = true)) {
            MailOutcome.NotConfigured(rawBody)
        } else {
            MailOutcome.BadRequest(rawBody.ifBlank { "Malformed request" })
        }
        401 -> MailOutcome.Unauthorized("Bad secret or unknown device")
        // The 403 prose names an unauthorized From, which is the one thing the user can act on.
        403 -> MailOutcome.BadRequest(rawBody.ifBlank { "Refused" })
        // Two PGP refusals share this status. clientSideNeeded is checked first to match the
        // server's own precedence: a client-custody account cannot encrypt server-side at all, so
        // its keyless recipients are beside the point and a pickup dialog would be nonsense.
        409 -> when {
            rawBody.contains(CLIENT_SIDE_NEEDED_MARKER, ignoreCase = true) ->
                MailOutcome.ClientSideNeeded(rawBody)
            rawBody.contains(REENROLLMENT_REQUIRED_MARKER, ignoreCase = true) ->
                MailOutcome.BadRequest(REENROLLMENT_REQUIRED_MESSAGE)
            rawBody.contains(PGP_STATE_CHANGED_MARKER, ignoreCase = true) ->
                MailOutcome.BadRequest(PGP_STATE_CHANGED_MESSAGE)
            else -> {
                val parsed = runCatching { json.decodeFromString<RelayPickupFallbackDto>(rawBody) }.getOrNull()
                if (parsed != null && parsed.keylessRecipients.isNotEmpty()) {
                    MailOutcome.PickupFallbackNeeded(parsed.keylessRecipients, parsed.error)
                } else {
                    // Deliberately not rawBody: an unrecognized 409 body is JSON, and raw JSON in
                    // a toast is worse than a generic sentence.
                    MailOutcome.BadRequest("Conflicting request")
                }
            }
        }
        // Plain text, and it distinguishes "SMTP failed" from "every pickup link failed to
        // deliver; nothing was sent" — a distinction a fixed string throws away.
        502 -> MailOutcome.UpstreamFailure(rawBody.ifBlank { "Upstream IMAP/SMTP failure" })
        503 -> MailOutcome.ServiceUnavailable(rawBody.ifBlank { "Mail relay is temporarily unavailable" })
        else -> MailOutcome.UpstreamFailure("Mail relay request failed ($code)")
    }

    /** [execute]'s shape for a body large enough that materialising it as a `String` matters.
     *  `parsed` is null on a malformed 200; `errorBody` carries the bounded failure text. */
    private fun <D, T> executeStreaming(
        request: Request,
        deserializer: kotlinx.serialization.DeserializationStrategy<D>,
        onResponse: (code: Int, parsed: D?, errorBody: String) -> MailOutcome<T>,
    ): MailOutcome<T> {
        val result = effectiveCallFactory().executeDecoding(request, json, deserializer, HEADER_RETRY_AFTER)
        val exception = result.exceptionOrNull()
        if (exception is javax.net.ssl.SSLPeerUnverifiedException) {
            return MailOutcome.CertificateMismatch(exception.message ?: "Certificate pin mismatch")
        }
        val response = result.getOrNull()
            ?: return MailOutcome.UpstreamFailure(exception?.message ?: "Network error")
        if (response.code == 429) return rateLimited(response.errorBody, response.retryAfter)
        return onResponse(response.code, response.decoded, response.errorBody)
    }

    private fun <T> execute(request: Request, onResponse: (code: Int, body: String) -> MailOutcome<T>): MailOutcome<T> {
        val result = effectiveCallFactory().executeSync(request) { response ->
            Triple(response.code, response.body?.string().orEmpty(), response.header(HEADER_RETRY_AFTER))
        }
        val exception = result.exceptionOrNull()
        if (exception is javax.net.ssl.SSLPeerUnverifiedException) {
            return MailOutcome.CertificateMismatch(exception.message ?: "Certificate pin mismatch")
        }
        val (code, body, retryAfter) = result.getOrNull()
            ?: return MailOutcome.UpstreamFailure(exception?.message ?: "Network error")
        if (code == 429) return rateLimited(body, retryAfter)
        return onResponse(code, body)
    }

    /** Null unless serverUrl is still https: re-checked per request, not only at pairing time. */
    private fun baseUrl(pairing: PairingData, path: String): HttpUrl? {
        if (pairingUrlHost(pairing.serverUrl) == null) return null
        return "${pairing.serverUrl.trimEnd('/')}$path".toHttpUrlOrNull()
    }
}

/** Same order of magnitude as the outbound cap in `ComposeActivity` and the server's own
 *  `MaxInboundMessageBytes`, so no legitimate attachment is refused. */
private const val MAX_ATTACHMENT_DOWNLOAD_BYTES = 25L * 1024 * 1024

/** Growth step for the unknown-length path; the first read usually settles it. */
private const val READ_BOUNDED_INITIAL_BYTES = 64 * 1024

/** Reads at most [limit] bytes, throwing if there was more; never allocates an oversized body.
 *
 *  Allocates the result ONCE, at the declared size, and reads straight into it. The previous shape
 *  filled an `okio.Buffer` and then called `readByteArray()`, which allocates a second array of the
 *  full size and copies — both live at that instant, so the true peak was 2 x limit (50 MB) while
 *  [org.kysecurity.mail.MemoryBudget] counted it as one 32 MB response. `Content-Length` is present
 *  on every attachment this relay serves, so the exact path below is the one that runs. */
internal fun readBounded(body: okhttp3.ResponseBody, limit: Long): ByteArray {
    val declared = body.contentLength()
    // Refused before a byte is read, rather than after reading `limit` of them.
    if (declared > limit) {
        throw IOException("Attachment is larger than the $limit byte download limit (declared $declared)")
    }
    val source = body.source()

    if (declared >= 0) {
        val bytes = ByteArray(declared.toInt())
        source.readFully(bytes)
        // A body longer than it declared is a framing lie, not an attachment.
        if (!source.exhausted()) {
            throw IOException("Attachment sent more than the $declared bytes it declared")
        }
        return bytes
    }

    // Chunked, so the size is unknown until EOF. Grows in place and doubles, capped at [limit]:
    // still one array rather than a chunk list plus a join, but a growth or the final trim briefly
    // holds two. This path does not run against the relay; it exists so a server that omits
    // Content-Length is handled rather than trusted.
    var bytes = ByteArray(minOf(READ_BOUNDED_INITIAL_BYTES.toLong(), limit).toInt())
    var size = 0
    while (true) {
        if (size == bytes.size) {
            if (size.toLong() >= limit) {
                // At the ceiling: one more readable byte means this was a prefix, not the body.
                if (!source.exhausted()) {
                    throw IOException("Attachment is larger than the $limit byte download limit")
                }
                return bytes
            }
            bytes = bytes.copyOf(minOf(bytes.size.toLong() * 2, limit).toInt())
        }
        val read = source.read(bytes, size, bytes.size - size)
        if (read == -1) break
        size += read
    }
    return if (size == bytes.size) bytes else bytes.copyOf(size)
}

private fun filenameFromDisposition(header: String?): String {
    if (header.isNullOrBlank()) return ""
    Regex("filename\\*=(?:UTF-8'')?\"?([^\";]+)\"?", RegexOption.IGNORE_CASE).find(header)?.let {
        return runCatching { java.net.URLDecoder.decode(it.groupValues[1], "UTF-8") }.getOrDefault(it.groupValues[1])
    }
    Regex("filename=\"?([^\";]+)\"?", RegexOption.IGNORE_CASE).find(header)?.let {
        return it.groupValues[1]
    }
    return ""
}

private fun MailAction.wireValue(): String = when (this) {
    MailAction.DELETE -> "delete"
    MailAction.ARCHIVE -> "archive"
    MailAction.SPAM -> "spam"
    MailAction.READ -> "read"
    MailAction.MOVE -> "move"
}

private fun MailDraft.toWireDto(): RelayMailRequestDto =
    RelayMailRequestDto(
        to = to,
        cc = cc,
        bcc = bcc,
        subject = subject,
        body = body,
        mode = mode,
        // The one place the outbound bytes become base64: the wire shape, built per send rather
        // than retained for the life of the compose screen. java.util.Base64, not android.util —
        // this file is JVM-unit-tested and the Android one returns stubs there (SourceRulesTest).
        attachments = attachments.map {
            RelayAttachmentDto(
                name = it.name,
                mimeType = it.mimeType,
                dataBase64 = java.util.Base64.getEncoder().encodeToString(it.bytes),
            )
        },
    )

/** Send-only mapping. [toWireDto] stays flagless because /api/mail/draft ignores these fields —
 *  see [MailDraft.allowPickupFallback]. */
private fun MailDraft.toSendWireDto(): RelayMailRequestDto =
    toWireDto().copy(sign = sign, encrypt = encrypt, allowPickupFallback = allowPickupFallback)

private fun RelayEmailDto.toUiEmail(tab: String): Email {
    val emailLabel = label.ifBlank { tab }
    return Email(
        id = messageId,
        subject = subject,
        sender = sender,
        preview = body.orEmpty().take(140),
        // Union, not a replacement: the label drives KeywordTabs, the wire list carries $Phishing.
        keywords = (keywords + emailLabel).filter { it.isNotBlank() }.toSet(),
        sentTo = sentTo,
        cc = cc,
        bcc = bcc,
        body = body,
        bodyMode = bodyMode,
        label = emailLabel,
        status = status,
        atUtc = atUtc,
        hasAttachments = hasAttachments,
        sourceMode = "relay",
        pgpEncrypted = pgpEncrypted,
        pgpSigned = pgpSigned,
        pgpVerified = pgpVerified,
        pgpSignerFingerprint = pgpSignerFingerprint,
        pgpDecryptError = pgpDecryptError,
    )
}
