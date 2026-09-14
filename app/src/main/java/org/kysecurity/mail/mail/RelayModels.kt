package org.kysecurity.mail.mail

import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.PrimitiveKind
import kotlinx.serialization.descriptors.PrimitiveSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive

/** Some deployments may emit `cursor` as a bare JSON number rather than a quoted string; decode
 *  either shape into a plain string token so callers never need to care which one the server sent. */
private object FlexibleCursorSerializer : KSerializer<String> {
    override val descriptor = PrimitiveSerialDescriptor("Cursor", PrimitiveKind.STRING)

    override fun serialize(encoder: Encoder, value: String) = encoder.encodeString(value)

    override fun deserialize(decoder: Decoder): String {
        val element = (decoder as JsonDecoder).decodeJsonElement()
        return (element as? JsonPrimitive)?.takeIf { it !is JsonNull }?.content.orEmpty()
    }
}

@Serializable
data class RelayEmailDto(
    val messageId: String = "",
    val sender: String = "",
    val sentTo: String = "",
    val cc: String = "",
    val bcc: String = "",
    val subject: String = "",
    // Null (not "") distinguishes an omitted body (delta "updated" entries) from a genuinely
    // empty one, so callers know not to overwrite/clear a locally cached body.
    val body: String? = null,
    val bodyMode: String = "",
    val label: String = "",
    // `omitempty` server-side, so an absent key means the message has no keywords.
    val keywords: List<String> = emptyList(),
    val status: String = "unread",
    val atUtc: String? = null,
    // Warm-path hint for the inbox paperclip badge; false when the server
    // hasn't warmed the message yet (see backend mailcache.Entry).
    val hasAttachments: Boolean = false,
    // Only present when the parent response has "delta": true — "new" or "updated"
    // (Mobile_Mail_Relay.md Part 5, delta/cursor sync v2).
    val changeType: String? = null,
    // pgpEncrypted with an EMPTY pgpDecryptError means client-protected, not a decrypt failure.
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
) {
    /** Redacted: the body is message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "RelayEmailDto(redacted)"
}

@Serializable
data class RelayInboxResponseDto(
    val tabs: List<String> = emptyList(),
    val byTab: Map<String, List<RelayEmailDto>> = emptyMap(),
    @Serializable(with = FlexibleCursorSerializer::class)
    val cursor: String = "",
    val delta: Boolean = false,
    val removed: List<String> = emptyList(),
)

@Serializable
data class RelayFolderDto(val path: String, val deletable: Boolean = true)

@Serializable
data class RelayFolderListResponseDto(val parent: String = "", val folders: List<RelayFolderDto> = emptyList())

@Serializable
data class RelayFolderCreateRequestDto(val parent: String, val name: String)

@Serializable
data class RelayFolderRenameRequestDto(val folder: String, val name: String)

@Serializable
data class RelayActionRequestDto(
    val action: String,
    val messageIds: List<String>,
    val mailbox: String,
    val targetMailbox: String? = null,
)

@Serializable
data class RelayActionFailureDto(val messageId: String = "", val error: String = "")

@Serializable
data class RelayActionResponseDto(
    val ok: Boolean = false,
    val action: String = "",
    val processed: Int = 0,
    val failed: List<RelayActionFailureDto> = emptyList(),
    val targetMailbox: String = "",
)

/** `to`/`cc`/`bcc` are comma-separated strings here, not arrays — differs from /api/inbox's
 *  response shape and from contact sync's array-of-objects shape (Mobile_Mail_Relay.md Part 6). */
@Serializable
data class RelayMailRequestDto(
    val to: String,
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val body: String,
    val mode: String = "plain",
    val attachments: List<RelayAttachmentDto> = emptyList(),
    /** Only /api/mail/send reads these three; /api/mail/draft ignores them, which is why
     *  [org.kysecurity.mail.mail.MailDraft] maps to this DTO through two different functions. */
    val sign: Boolean = false,
    val encrypt: Boolean = false,
    val allowPickupFallback: Boolean = false,
) {
    /** Redacted: the body is the user's outgoing message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "RelayMailRequestDto(redacted)"
}

/** One pre-encrypted delivery for POST /api/mail/send-pgp. */
@Serializable
data class RelayClientEncryptedDeliveryDto(
    val recipients: List<String>,
    val ciphertext: String,
)

/** POST /api/mail/send-pgp. [subject] is a fixed placeholder; the real one is inside the ciphertext. */
@Serializable
data class RelayClientEncryptedRequestDto(
    val from: String,
    val subject: String,
    val mode: String = "html",
    val to: List<String> = emptyList(),
    val cc: List<String> = emptyList(),
    val bcc: List<String> = emptyList(),
    val deliveries: List<RelayClientEncryptedDeliveryDto> = emptyList(),
    val sentCopy: String = "",
    val sentCopyEncrypted: Boolean = false,
)

/** Outgoing attachment wire shape accepted by /api/mail/send and /api/mail/draft. */
@Serializable
data class RelayAttachmentDto(
    val name: String,
    val mimeType: String,
    val dataBase64: String,
)

/** One received attachment's metadata from GET /api/mail/attachments. */
@Serializable
data class RelayAttachmentInfoDto(
    val index: Int = 0,
    val name: String = "",
    val mimeType: String = "",
    val size: Int = 0,
)

@Serializable
data class RelayAttachmentListResponseDto(
    val ok: Boolean = false,
    val attachments: List<RelayAttachmentInfoDto> = emptyList(),
)

/** One message's body from GET /api/mail/body, the on-demand counterpart to `bodies=0`.
 *
 *  [bodyMode] is `html`, `plain`, or absent — absent means the server could not tell from the MIME
 *  parse, which is NOT the same as plain, and must never be resolved by sniffing the text: a
 *  plain-text message containing an address literal like `<user@example.com>` parses as an unknown
 *  tag and the address vanishes from what the user is shown.
 *
 *  No recipients here: the endpoint carries body and bodyMode only. Reply All's `to`/`cc` come from
 *  the cached row — see [MailRepository.fetchBody]. */
@Serializable
data class RelayMessageBodyDto(val body: String = "", val bodyMode: String = "") {
    /** Redacted: [body] is the message the user is reading. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "RelayMessageBodyDto(redacted)"
}

@Serializable
data class RelaySendResponseDto(val ok: Boolean = false, val sentSaved: Boolean = false, val warning: String = "")

/** The 409 body /api/mail/send returns when recipients have no usable PGP key. Both PGP refusals
 *  are 409 and are told apart by which field is present, never by status or error prose — the
 *  prose is user-facing copy and may be reworded. */
@Serializable
data class RelayPickupFallbackDto(
    val error: String = "",
    val keylessRecipients: List<String> = emptyList(),
    val pickupFallbackAvailable: Boolean = false,
)

/** Closed encrypted-draft wire shape; never serialize a plaintext MailDraft here. */
@Serializable
data class RelayClientEncryptedDraftDto(val to: String, val pgpDraft: String) {
    override fun toString(): String = "RelayClientEncryptedDraftDto(redacted)"
}
