package org.kysecurity.mail.mail

import org.jsoup.Jsoup
import org.jsoup.nodes.Document
import org.jsoup.safety.Safelist

// The composer WebView has JS on and an `editor` bridge, so quoted sender HTML must be sanitized.
object QuotedHtmlSanitizer {

    private val safelist: Safelist = Safelist.relaxed()
        // `relaxed()` permits <img>, and the composer has network access: a tracking beacon.
        .removeTags("img")

    fun sanitize(html: String): String {
        if (html.isBlank()) return ""
        // Empty base URI: relative links in the quote stay relative rather than being resolved
        // against a host we would have to invent.
        // No pretty-printing: it re-indents, so re-sanitizing the output could add whitespace and
        // the result would not be a fixed point (Run4SanitizerMxssProbeTest). A new
        // OutputSettings per call, because the object is mutable and this runs off the UI thread.
        return runCatching { Jsoup.clean(html, "", safelist, Document.OutputSettings().prettyPrint(false)) }
            // A quote we cannot parse is not a quote we may pass through. Failing to the escaped
            // source text keeps the user's context while guaranteeing nothing executes.
            .getOrElse { org.jsoup.parser.Parser.unescapeEntities(html, false).let(::escapeAsText) }
    }

    private fun escapeAsText(text: String): String =
        text.replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\"", "&quot;")
}
