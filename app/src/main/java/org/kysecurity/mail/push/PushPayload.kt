package org.kysecurity.mail.push

import kotlinx.serialization.Serializable

@Serializable
data class PushPayload(
    val messageId: String,
    val senderName: String,
    val emailSubject: String,
    val keywords: List<String>,
    val receivedAtEpochMs: Long,
)

object PushPayloadParser {

    /** Bounded for the same reasons [MfaChallengePayloadParser] bounds its own fields, on the same
     *  delivery channel: these strings are rendered into a notification AND serialised into the
     *  `push_state_secure` store, [HISTORY_LIMIT] of them at a time. Unbounded, a hostile relay turns
     *  that file into something the app OOMs on before any code that could delete it runs. */
    internal const val MAX_MESSAGE_ID_LENGTH = 256
    internal const val MAX_HEADER_LENGTH = 512

    /** A notification shows one line of each; the rest is retained cost, never displayed. */
    internal const val MAX_KEYWORDS = 32
    internal const val MAX_KEYWORD_LENGTH = org.kysecurity.mail.KeywordSettings.MAX_KEYWORD_LENGTH

    /** The one place relay-supplied strings get bounded. Every delivery path — FCM push via
     *  [parse], App Pull via `PullNotification.toPushPayload` — must go through this before the
     *  payload is notified or persisted, or the unbounded path becomes the one the relay picks. */
    internal fun sanitize(payload: PushPayload): PushPayload = payload.copy(
        messageId = payload.messageId.trim().take(MAX_MESSAGE_ID_LENGTH),
        senderName = payload.senderName.trim().take(MAX_HEADER_LENGTH),
        emailSubject = payload.emailSubject.trim().take(MAX_HEADER_LENGTH),
        keywords = boundKeywords(payload.keywords.asSequence()),
    )

    /** Sequence in, so a hostile CSV is cut off rather than materialised whole. */
    private fun boundKeywords(raw: Sequence<String>): List<String> = raw
        .map { it.trim() }
        .filter { it.isNotBlank() && it.length <= MAX_KEYWORD_LENGTH }
        .take(MAX_KEYWORDS)
        .toList()

    fun parse(data: Map<String, String>, nowEpochMs: Long = System.currentTimeMillis()): PushPayload? {
        // Accept either casing: the server sends "Keywords" while every other field is camelCase.
        val keywordsCsv = (data["keywords"] ?: data["Keywords"]).orEmpty()

        val payload = sanitize(
            PushPayload(
                messageId = data["messageId"].orEmpty(),
                senderName = data["senderName"].orEmpty(),
                emailSubject = data["emailSubject"].orEmpty(),
                keywords = boundKeywords(keywordsCsv.splitToSequence(',')),
                receivedAtEpochMs = nowEpochMs,
            )
        )
        return payload.takeIf { it.messageId.isNotBlank() }
    }

    fun title(payload: PushPayload): String {
        return payload.senderName.ifBlank { "New email" }
    }

    fun body(payload: PushPayload): String {
        return payload.emailSubject.ifBlank { "You received a new labeled email" }
    }
}

