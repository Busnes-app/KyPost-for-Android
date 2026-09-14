package org.kysecurity.mail.mail

import org.kysecurity.mail.Email

sealed class MailOutcome<out T> {
    data class Success<T>(val value: T) : MailOutcome<T>()

    /** Relay 400 "imap configuration is required*" — direct the user to the web app, never a form. */
    data class NotConfigured(val message: String) : MailOutcome<Nothing>()

    /** Relay/pairing 401 — re-pair the device. */
    data class Unauthorized(val message: String) : MailOutcome<Nothing>()

    /** Relay 503 (either flavor: no PAIRING_SECRET, or IMAP client unavailable). */
    data class ServiceUnavailable(val message: String) : MailOutcome<Nothing>()

    /** Relay 502 upstream IMAP/SMTP failure — safe to retry with backoff. */
    data class UpstreamFailure(val message: String) : MailOutcome<Nothing>()

    /** Any other 400, or a local validation failure. */
    data class BadRequest(val message: String) : MailOutcome<Nothing>()

    /** TLS certificate didn't match the pin captured at pairing time — could be a legitimate
     *  cert rotation on the user's own server, or an active MITM; either way, do not silently
     *  fall back to trusting it. */
    data class CertificateMismatch(val message: String) : MailOutcome<Nothing>()

    /** Relay 409 `clientSideNeeded` — the account's PGP key is client-held; this app has none. */
    data class ClientSideNeeded(val message: String) : MailOutcome<Nothing>()

    /** Relay 409 `keylessRecipients`. Nothing was delivered; re-sending with the opt-in is safe. */
    data class PickupFallbackNeeded(
        val keylessRecipients: List<String>,
        val message: String,
    ) : MailOutcome<Nothing>()

    /** The relay accepted the request and answered 200, but named this message in `failed[]` (or
     *  processed nothing at all) — the mailbox is read-only, the UID is gone, IMAP refused. The
     *  request reached the server, so this must never be worded as a connectivity problem. */
    data class ActionRejected(val messageId: String, val message: String) : MailOutcome<Nothing>()

    /** Relay 429 with Retry-After — the server's per-device lockout after repeated bad
     *  credentials. [retryAfterSeconds] is null when the header was absent or unparseable;
     *  callers should still back off rather than retrying immediately. */
    data class RateLimited(val message: String, val retryAfterSeconds: Long?) : MailOutcome<Nothing>()
}

/** Wording tailored per failure kind, per Mobile_Mail_Relay.md's error table — never auto-clears
 *  pairing on 401/503, only points the user at the places that would (Settings/PushPairingActivity). */
fun MailOutcome<*>.userFacingMessage(): String? = when (this) {
    is MailOutcome.Success -> null
    is MailOutcome.NotConfigured -> "Set up your mail account on the web app first"
    is MailOutcome.Unauthorized -> "Device pairing expired or invalid — re-pair this device in Settings"
    is MailOutcome.ServiceUnavailable -> "Mail relay is unavailable: $message"
    is MailOutcome.UpstreamFailure -> "Couldn't reach the mail server: $message"
    is MailOutcome.BadRequest -> message
    // Reconnect, NOT unpair/re-pair. Both end the current pairing, but only one keeps the mailbox:
    // reconnectToServer clears the credential and the pin and destroys nothing, while unpairing runs
    // the account-replacement purge — and a purge that cannot prove itself escalates to erasing the
    // device. Recommending the destructive ceremony for a routine certificate renewal is how a
    // renewed cert became a wiped mailbox.
    is MailOutcome.CertificateMismatch -> "This server's certificate has changed since pairing — if you expect this (e.g. you renewed your server's certificate), use \"Reconnect to server\" on the pairing screen. It keeps your downloaded mail, contacts and keys."
    is MailOutcome.ClientSideNeeded -> "This account's PGP key is end-to-end protected, so signing and encryption aren't available on mobile. Send without them, or use webmail."
    is MailOutcome.PickupFallbackNeeded ->
        "No PGP key on file for ${keylessRecipients.joinToString(", ")} — nothing was sent."
    // The relay's own words for why this one message could not be actioned; the caller already
    // prefixes the action ("Archive failed: ...").
    is MailOutcome.ActionRejected -> message
    is MailOutcome.RateLimited -> retryAfterSeconds
        ?.let { "Too many failed attempts — try again in ${formatRetryAfter(it)}" }
        ?: "Too many failed attempts — try again later"
}

internal fun formatRetryAfter(seconds: Long): String = when {
    seconds < 60 -> "$seconds seconds"
    seconds < 120 -> "a minute"
    else -> "${seconds / 60} minutes"
}

/** Where the next fetch should resume from, carried back as a *fact* rather than written by the
 *  fetch itself. [MailRepository] commits it only after the messages it describes are durable in
 *  Room — advancing it first meant a failed reconcile made the relay skip that mail forever
 *  (until the daily self-heal). [subscriberId] is the one the fetch actually authenticated as, so
 *  a re-pair mid-fetch cannot scope the cursor to the wrong account. */
data class MailCheckpoint(
    val subscriberId: String,
    /** Blank when the relay sent no cursor — nothing to advance. */
    val cursor: String,
    /** True when this fetch asked for since=0, so the daily full-resync stamp is due. */
    val wasFullResync: Boolean,
)

data class MailFetchResult(
    val tabs: List<String>,
    val messages: List<Email>,
    // The rest only matter when isDelta is true (Mobile_Mail_Relay.md Part 5 v2); a false/default
    // value means `messages` is a full snapshot, exactly like the pre-delta response shape.
    val isDelta: Boolean = false,
    val updatedMessageIds: Set<String> = emptySet(),
    val removedMessageIds: List<String> = emptyList(),
    // True when we sent since=0. Older relays label such a response `delta: true`, so trust this.
    val isFullWindow: Boolean = false,
    /** Null only for sources that have no cursor to keep (tests, non-relay sources). */
    val checkpoint: MailCheckpoint? = null,
)
data class FolderInfo(val path: String, val deletable: Boolean)
data class FolderListResult(val parent: String, val folders: List<FolderInfo>)

enum class MailAction { DELETE, ARCHIVE, SPAM, READ, MOVE }

data class MailActionOutcome(val processed: Int, val failed: List<Pair<String, String>>)

data class MailDraft(
    val to: String,
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val body: String,
    val mode: String = "plain",
    val attachments: List<OutgoingAttachment> = emptyList(),
    /** Server-side PGP signing. Requires the account to have a PGP identity; the relay answers
     *  400 (plain text) if asked to sign without one. */
    val sign: Boolean = false,
    val encrypt: Boolean = false,
    /** Per-message opt-in: the fallback stores this plaintext on the server for up to seven days. */
    val allowPickupFallback: Boolean = false,
) {
    /** Redacted: the body is the user's outgoing message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "MailDraft(redacted)"
}

/** One attachment on its way out, held as DECODED bytes.
 *
 *  It used to carry base64 in a `String`, which was the wire form, retained for as long as the
 *  compose screen lived. That cost ~2.67x the file — base64 is 4/3, and ART stores `String` as
 *  UTF-16 — and, worse, a `String` cannot be zeroed, so a security wipe could drop the reference
 *  and nothing more. Encoding now happens at the two wire boundaries that need it
 *  (`RelayMailSource.toWireDto` and `buildProtectedContent`) and nowhere else.
 *
 *  Not a `data class`: the generated `equals`/`hashCode` over [bytes] would be identity behind a
 *  structural-looking API, and the generated `toString` would print decrypted mail. Enforced by
 *  `SourceRulesTest`. */
class OutgoingAttachment(
    val name: String,
    val mimeType: String,
    val bytes: ByteArray,
) {
    val size: Int get() = bytes.size

    /** Overwrites the plaintext in place. Only for a session boundary — see [ComposeDraftCache]. */
    fun wipe() = java.util.Arrays.fill(bytes, 0)

    /** Redacted: the bytes are an attachment the user is sending. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "OutgoingAttachment(redacted)"
}

/** Only an already self-encrypted MIME message crosses the draft transport boundary. */
data class ClientEncryptedDraft(val to: String, val pgpDraft: String) {
    override fun toString(): String = "ClientEncryptedDraft(redacted)"
}

data class MailSendOutcome(val sentSaved: Boolean, val warning: String)

data class ClientEncryptedDelivery(val recipients: List<String>, val ciphertext: String)

// One delivery per BCC recipient: a shared ciphertext exposes every BCC recipient's key id.
data class ClientEncryptedMessage(
    val from: String,
    val to: List<String>,
    val cc: List<String>,
    val bcc: List<String>,
    val deliveries: List<ClientEncryptedDelivery>,
    /** The same message encrypted to the sender's own key. Never a plaintext body: the server
     *  refuses an unencrypted copy, and storing one would hand back in the clear exactly what the
     *  deliveries were protecting. */
    val sentCopy: String,
    val mode: String = "html",
)

data class MailMessageBody(
    val html: String,
    val bodyMode: String = "",
    val toAddresses: List<String>,
    val ccAddresses: List<String>,
) {
    /** Redacted: the html is message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "MailMessageBody(redacted)"
}

/** One received attachment's metadata (no content), from GET /api/mail/attachments. */
data class AttachmentInfo(val index: Int, val name: String, val mimeType: String, val size: Int)

/** Not a `data class`: the generated equals/hashCode would compare [bytes] by identity. */
class DownloadedAttachment(val name: String, val mimeType: String, val bytes: ByteArray)

interface MailSource {
    /** [forceFullResync] requests since=0 (full re-fetch reported in delta shape) regardless of
     *  any persisted cursor — the documented self-heal for a missed removal notification. */
    fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean = false): MailOutcome<MailFetchResult>
    fun listFolders(parent: String?): MailOutcome<FolderListResult>
    fun createFolder(parent: String, name: String): MailOutcome<Unit>
    fun renameFolder(folder: String, name: String): MailOutcome<Unit>
    fun deleteFolder(folder: String): MailOutcome<Unit>
    fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String? = null,
    ): MailOutcome<MailActionOutcome>
    fun saveDraft(draft: MailDraft): MailOutcome<Unit>
    fun saveClientEncryptedDraft(draft: ClientEncryptedDraft): MailOutcome<Unit>
    fun sendMail(draft: MailDraft): MailOutcome<MailSendOutcome>

    /** Relays ciphertext this device already built; a different endpoint and failure set. */
    fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome>
    fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody>
    fun listAttachments(messageId: String, folder: String): MailOutcome<List<AttachmentInfo>>
    fun downloadAttachment(messageId: String, folder: String, index: Int): MailOutcome<DownloadedAttachment>
}
