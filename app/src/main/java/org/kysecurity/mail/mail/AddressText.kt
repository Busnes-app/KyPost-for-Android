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

/** Sender, To and Cc without the user's [own] addresses, unless nobody else is left. */
fun replyAllRecipients(sender: String, to: List<String>, cc: List<String>, own: List<String>): List<String> {
    val all = (listOf(sender) + to + cc).map(::addressFromHeader)
        .filter { it.isNotBlank() }
        .distinctBy { it.lowercase() }
    val mine = own.mapTo(HashSet()) { addressFromHeader(it).lowercase() }
    return all.filterNot { it.lowercase() in mine }.ifEmpty { all }
}

/** `you+tag@example.org` without its tag; any other address as it is. */
fun plusBase(address: String): String {
    val at = address.lastIndexOf('@')
    val plus = if (at < 0) -1 else address.substring(0, at).indexOf('+')
    return if (plus < 0) address else address.substring(0, plus) + address.substring(at)
}

/** The From a reply sends from, so a reply to a masked or plus address never shows the primary.
 *  With the receipt's [delivered] addresses (native mail, Bcc included): the To/Cc address that
 *  names one keeps its tag, else the delivered own address; null when none is the user's, so they
 *  must choose. Without a receipt (external IMAP, Sent) the user's own To/Cc address is used, and
 *  "" keeps the account default. The web client's rule (frontend/src/pages/read/compose.ts). */
fun replyFromAddress(sentTo: String, cc: String, own: List<String>, delivered: List<String>?): String? {
    val mine = own.mapTo(HashSet()) { it.lowercase() }
    fun isMine(address: String) = address in mine || plusBase(address) in mine
    val headers = org.kysecurity.mail.splitAddresses(sentTo, cc).map { addressFromHeader(it).lowercase() }.filter { it.isNotBlank() }
    if (delivered == null) return headers.firstOrNull(::isMine) ?: ""
    val got = delivered.mapTo(LinkedHashSet()) { it.lowercase() }
    return headers.firstOrNull { (it in got || plusBase(it) in got) && isMine(it) } ?: got.firstOrNull { it in mine }
}
