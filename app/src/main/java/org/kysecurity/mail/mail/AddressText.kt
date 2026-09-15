package org.kysecurity.mail.mail

/** One header, one line: a display name carrying CR/LF or a bidi override could otherwise forge
 *  a labelled line ("Cc: ceo@...") or reverse the shown address. Controls, format characters,
 *  and the Unicode line and paragraph separators become a single space. */
fun displayHeaderText(raw: String): String = HEADER_CONTROLS.replace(raw, " ").trim()

private val HEADER_CONTROLS = Regex("[\\p{Cc}\\p{Cf}\\p{Zl}\\p{Zp}]+")

// The LAST angle-addr is the real address (RFC 5322); rule shared verbatim with webmail/Linux.
fun addressFromHeader(raw: String): String {
    val value = raw.trim()
    if (value.isEmpty()) return ""
    val close = value.lastIndexOf('>')
    val open = if (close == -1) -1 else value.lastIndexOf('<', close)
    val candidate = if (open != -1 && close > open) {
        value.substring(open + 1, close).trim()
    } else {
        value
    }
    return if (candidate.contains('@')) candidate else ""
}
