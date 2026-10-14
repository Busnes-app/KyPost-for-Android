package org.kysecurity.mail.data

/** An [EmailEntity] without its body, for the list: a cached body can be megabytes, and the
 *  list repaints often. The reader fetches the body by id. */
data class EmailListRow(
    val messageId: String,
    val folder: String,
    val sender: String,
    val sentTo: String,
    val cc: String,
    val bcc: String,
    val subject: String,
    val preview: String,
    val hasBody: Boolean,
    val bodyMode: String,
    val label: String,
    val keywordsJson: String,
    val status: String,
    val atUtc: String?,
    val wokenAt: String?,
    val hasAttachments: Boolean,
    val sourceMode: String,
    val pgpEncrypted: Boolean,
    val pgpSigned: Boolean,
    val pgpVerified: Boolean,
    val pgpSignerFingerprint: String,
    val pgpDecryptError: String,
) {
    /** Redacted: the preview is cached message content. */
    override fun toString(): String = "EmailListRow(redacted)"
}
