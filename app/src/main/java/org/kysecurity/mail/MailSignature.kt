package org.kysecurity.mail

import android.content.Context

/** What a compose window opens for; decides whether the signature goes in. */
internal enum class ComposeKind { NEW, REPLY, FORWARD }

/** Why a signature text is refused, mirroring KyPost-Server's `config/signatures.go`. */
internal enum class SignatureProblem { TOO_LONG, CONTROL_CHARACTER }

/**
 * This device's plain-text signature. It is separate from the web signature on the server, which
 * the app never fetches: it lives in ordinary app preferences, is not synced, and leaves the
 * device only inside a message body. Account-scoped: the pairing purge deletes the file.
 */
internal data class MailSignature(
    val enabled: Boolean = false,
    val text: String = "",
    val onReply: Boolean = true,
    val onForward: Boolean = true,
) {
    /** The text to put in a [kind] message, or "" for none. */
    fun textFor(kind: ComposeKind): String = when {
        !enabled || text.isBlank() || signatureProblem(text) != null -> ""
        kind == ComposeKind.REPLY && !onReply -> ""
        kind == ComposeKind.FORWARD && !onForward -> ""
        else -> text
    }

    companion object {
        const val PREFS_NAME = "org.kysecurity.mail.signature"
        const val MAX_CHARS = 2000
        private const val KEY_TEXT = "signature"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_ON_REPLY = "on_reply"
        private const val KEY_ON_FORWARD = "on_forward"

        fun read(context: Context): MailSignature {
            val prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
            val text = prefs.getString(KEY_TEXT, null).orEmpty()
            return MailSignature(
                // Before the switch existed a saved signature was always added, so it stays on.
                enabled = prefs.getBoolean(KEY_ENABLED, text.isNotBlank()),
                text = text,
                onReply = prefs.getBoolean(KEY_ON_REPLY, true),
                onForward = prefs.getBoolean(KEY_ON_FORWARD, true),
            )
        }

        /** Saves [signature]; its text must already pass [signatureProblem]. */
        fun save(context: Context, signature: MailSignature) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE).edit()
                .putBoolean(KEY_ENABLED, signature.enabled)
                .putString(KEY_TEXT, normalizeSignature(signature.text))
                .putBoolean(KEY_ON_REPLY, signature.onReply)
                .putBoolean(KEY_ON_FORWARD, signature.onForward)
                .apply()
        }
    }
}

internal fun normalizeSignature(text: String): String = text.replace("\r\n", "\n")

/** The server's rules for signature text: at most [MailSignature.MAX_CHARS] characters, no control
 *  characters except newline and tab, and no bidirectional override or isolate controls. */
internal fun signatureProblem(text: String): SignatureProblem? {
    val normalized = normalizeSignature(text)
    if (normalized.codePointCount(0, normalized.length) > MailSignature.MAX_CHARS) return SignatureProblem.TOO_LONG
    val refused = normalized.codePoints().anyMatch { cp ->
        (Character.isISOControl(cp) && cp != '\n'.code && cp != '\t'.code) || isBidiControl(cp)
    }
    return if (refused) SignatureProblem.CONTROL_CHARACTER else null
}

/** Invisible characters that reorder the text around them, so a recipient could read something
 *  other than what the settings screen shows. */
private fun isBidiControl(cp: Int): Boolean = cp in 0x202A..0x202E || cp in 0x2066..0x2069

/**
 * Places [signatureText] as web does (docs/SIGNATURES.md in KyPost-Server): below the line the user
 * types on, with a blank line before it, and above a reply's or forward's quote with a blank line
 * between. The quote already opens with that blank line. No `-- ` delimiter is added. The text is
 * escaped: the editor renders HTML, and a signature is typed text.
 */
internal fun withSignature(bodyHtml: String, signatureText: String): String {
    if (signatureText.isBlank()) return bodyHtml
    val block = "<br><br>" + normalizeSignature(signatureText).split('\n').joinToString("<br>", transform = ::escapeHtml)
    return if (bodyHtml.isBlank() || bodyHtml.startsWith("<br>")) block + bodyHtml else bodyHtml + block
}

private fun escapeHtml(text: String): String = buildString {
    for (c in text) {
        when (c) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&#39;")
            else -> append(c)
        }
    }
}

/** True when [html] shows nothing but [signatureText]: no other text and no image. Only a short body
 *  can be one, so a long one is never parsed (this runs on the main thread in onStop). */
internal fun isUntouchedSignatureBody(html: String, signatureText: String): Boolean {
    if (html.length > 4 * signatureText.length + 256) return false
    val doc = runCatching { org.jsoup.Jsoup.parseBodyFragment(html) }.getOrNull() ?: return false
    if (doc.body().select("img, video, audio, iframe, object, embed").isNotEmpty()) return false
    fun words(text: String) = text.replace('\u00a0', ' ').split(Regex("\\s+")).filter { it.isNotEmpty() }
    return words(doc.body().text()) == words(normalizeSignature(signatureText))
}
