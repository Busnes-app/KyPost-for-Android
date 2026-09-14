package org.kysecurity.mail.pgp

import jakarta.mail.Part
import jakarta.mail.Session
import jakarta.mail.internet.MimeMessage
import jakarta.mail.internet.MimeMultipart
import java.io.ByteArrayInputStream
import java.util.Properties

/** One attachment part out of a decrypted message. Not a data class: identity equals over [bytes],
 *  and [toString] is redacted. Enforced by `SourceRulesTest`. */
internal class DecryptedAttachment(
    val name: String,
    val mimeType: String,
    val bytes: ByteArray,
    /** The `Content-ID` without its angle brackets, for `cid:` references in the html part. */
    val contentId: String?,
) {
    override fun toString(): String = "DecryptedAttachment(redacted)"
}

/** Both kept: a message with only a plain part must not render as an empty page. */
internal data class DecryptedBody(
    val html: String?,
    val plain: String?,
    /** MIME mode paired with the selected body; never infer this from its characters. */
    val bodyMode: String = "",
    /** The real subject from the encrypted part's protected headers, when the sender used them.
     *  The outer envelope subject is a placeholder for KyPost-to-KyPost mail. */
    val protectedSubject: String?,
    val attachments: List<DecryptedAttachment> = emptyList(),
    /** True when a part was dropped for size or count. The screen says so; silence would show a
     *  message that appears to have fewer files than it does. */
    val attachmentsOmitted: Boolean = false,
) {
    /** Redacted: every field is a decrypted message. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "DecryptedBody(redacted)"
}

/** Returns null rather than throwing; unparsed bytes never reach a WebView. */
internal object PgpMimeReader {

    /** A sender chooses the part count; fifty is past any real message and cheap to hold. */
    const val MAX_ATTACHMENT_PARTS = 50

    /** Total decoded attachment bytes retained from one message. */
    val attachmentByteCap: Long = org.kysecurity.mail.MemoryBudget.DECRYPTED_ATTACHMENT_BYTES

    fun read(mime: ByteArray): DecryptedBody? = runCatching {
        val session = Session.getInstance(Properties())
        val message = MimeMessage(session, ByteArrayInputStream(mime))

        var html: String? = null
        var plain: String? = null
        val attachments = ArrayList<DecryptedAttachment>()
        var omitted = false
        var retained = 0L

        fun collect(part: Part) {
            if (attachments.size >= MAX_ATTACHMENT_PARTS) { omitted = true; return }
            val remaining = (attachmentByteCap - retained).coerceAtLeast(0L)
            // Bounded read; null means the part alone would cross the ceiling, and it is dropped
            // whole rather than truncated. A partial file is worse than a missing one.
            val bytes = runCatching {
                PgpDecryptor.readAllWithLimit(part.inputStream, remaining.coerceAtMost(Int.MAX_VALUE.toLong()).toInt())
            }.getOrNull()
            if (bytes == null) { omitted = true; return }
            retained += bytes.size
            val name = runCatching { part.fileName }.getOrNull()?.takeIf { it.isNotBlank() } ?: "attachment"
            val mimeType = runCatching { part.contentType }.getOrNull()
                ?.substringBefore(';')?.trim()?.lowercase()?.takeIf { it.isNotBlank() }
                ?: "application/octet-stream"
            val contentId = runCatching { part.getHeader("Content-ID") }.getOrNull()
                ?.firstOrNull()?.trim()?.removePrefix("<")?.removeSuffix(">")?.takeIf { it.isNotBlank() }
            attachments += DecryptedAttachment(name, mimeType, bytes, contentId)
        }

        /** A `text/html` or `text/plain` leaf is a body candidate unless disposition says
         *  otherwise: a `name=` param or `Content-ID` on a text part never makes it a file — many
         *  mailers stamp both on every part, including the body. Non-text, non-multipart leaves
         *  are attachments regardless of headers. */
        fun isAttachment(part: Part): Boolean {
            val disposition = runCatching { part.disposition }.getOrNull()?.lowercase()
            if (disposition == Part.ATTACHMENT) return true
            if (part.isMimeType("text/html") || part.isMimeType("text/plain")) return false
            return !part.isMimeType("multipart/*")
        }

        fun walk(content: Any?) {
            if (content !is MimeMultipart) return
            for (i in 0 until content.count) {
                val part = content.getBodyPart(i)
                if (isAttachment(part)) { collect(part); continue }
                val body = runCatching { part.content }.getOrNull()
                when {
                    part.isMimeType("text/html") -> {
                        val s = body as? String
                        // A blank part is real content, but a later non-blank sibling must win.
                        if (s != null && (html == null || html!!.isBlank())) html = s
                    }
                    part.isMimeType("text/plain") -> {
                        val s = body as? String
                        if (s != null && (plain == null || plain!!.isBlank())) plain = s
                    }
                    body is MimeMultipart -> walk(body)
                }
            }
        }

        val hadContentTypeHeader = message.getHeader("Content-Type", null) != null
        val content = message.content
        when {
            message.isMimeType("text/html") -> html = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            message.isMimeType("text/plain") -> plain = (content as? String)
                ?.let { if (hadContentTypeHeader) it else it.takeIf(String::isNotBlank) }
            else -> walk(content)
        }

        // An attachment is content: a files-only message renders an empty body and its chips.
        if (html == null && plain == null) {
            if (attachments.isEmpty()) return null
            plain = ""
        }
        DecryptedBody(
            html = html,
            plain = plain,
            bodyMode = if (html != null) "html" else "plain",
            protectedSubject = message.subject?.takeIf { it.isNotBlank() },
            attachments = attachments,
            attachmentsOmitted = omitted,
        )
    }.getOrNull()
}
