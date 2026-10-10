package org.kysecurity.mail.data

import androidx.room.Entity

/** Keyed by folder **and** [messageId]: the relay's id is an IMAP UID, unique only within one
 *  mailbox, so INBOX and Archive can both hold `42`. A single-column key let a refresh of either
 *  folder overwrite or relocate the other's row.
 *
 *  ponytail: still not UIDVALIDITY-aware — the relay does not expose it, and a client cannot
 *  invent it. A UIDVALIDITY reset therefore leaves rows keyed to ids the server has reused; the
 *  daily full resync (`MailFetchResult.isFullWindow`) rewrites the window and prunes the rest of
 *  it within a day, but rows outside the window ([inWindow] false) are never pruned and stay
 *  stale. Upgrade path: have the relay return UIDVALIDITY (or a stable opaque id) and add it to
 *  this key.
 */
@Entity(tableName = "emails", primaryKeys = ["folder", "messageId"])
data class EmailEntity(
    val messageId: String,
    val folder: String,
    val sender: String,
    val sentTo: String = "",
    val cc: String = "",
    val bcc: String = "",
    val subject: String,
    val preview: String = "",
    val body: String? = null,
    val bodyMode: String = "",
    val label: String = "",
    val keywordsJson: String = "[]",
    val status: String = "unread",
    val atUtc: String? = null,
    val hasAttachments: Boolean = false,
    val sourceMode: String,
    // Cached so a client-protected message is not indistinguishable from one with an empty body.
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
    /** False once the row is older than the relay's window (paged in, or reported `agedOut`). A
     *  snapshot lists only the window, so absence from one proves nothing about these rows. */
    val inWindow: Boolean = true,
) {
    /** Redacted: the preview and body are cached message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "EmailEntity(redacted)"
}
