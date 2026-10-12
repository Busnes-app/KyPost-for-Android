package org.kysecurity.mail

data class Email(
    val id: String,
    val subject: String,
    val sender: String,
    val preview: String,
    val keywords: Set<String> = emptySet(),
    val folder: String = "",
    val sentTo: String = "",
    val cc: String = "",
    val bcc: String = "",
    val body: String? = null,
    /** MIME mode of [body], supplied by the relay when known: `html` or `plain`. */
    val bodyMode: String = "",
    val label: String = "",
    val status: String = "unread",
    val atUtc: String? = null,
    /** Set while a woken snooze is pinned: the list sorts by it, the row still shows [atUtc]. */
    val wokenAt: String? = null,
    val hasAttachments: Boolean = false,
    val sourceMode: String = "relay",
    val pgpEncrypted: Boolean = false,
    val pgpSigned: Boolean = false,
    val pgpVerified: Boolean = false,
    val pgpSignerFingerprint: String = "",
    val pgpDecryptError: String = "",
) {
    /** Redacted: the preview and body are message content. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "Email(redacted)"
}
