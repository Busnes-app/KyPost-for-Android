package org.kysecurity.mail.contacts

const val VCARD_MIME_TYPE = "text/vcard"

enum class VCardVersion(val number: String) { V4("4.0"), V3("3.0") }

private val ISO_DATE = Regex("""\d{4}-\d{2}-\d{2}""")

/** RFC 6350 / RFC 2426 text for [contacts]. ponytail: covers name, org, title, email, phone,
 *  address, URL, birthday and note; IMs, relations, events, custom fields, pronouns, phonetic
 *  names, PGP keys, photos and groups are not exported. Add a property here and in the parser. */
fun writeVCards(contacts: List<ContactDto>, version: VCardVersion): String = buildString {
    contacts.forEach { appendVCard(it, version) }
}

private fun StringBuilder.appendVCard(c: ContactDto, version: VCardVersion) {
    line("BEGIN:VCARD")
    line("VERSION:${version.number}")
    line("FN:${escapeText(c.fn)}")
    line("N:" + listOf(c.familyName, c.givenName, c.middleName, c.prefix, c.suffix).joinToString(";") { escapeText(it.orEmpty()) })
    c.nickname.ifPresent { line("NICKNAME:${escapeText(it)}") }
    if (!c.org.isNullOrBlank() || !c.department.isNullOrBlank()) {
        val unit = c.department.takeUnless { it.isNullOrBlank() }?.let { ";" + escapeText(it) }.orEmpty()
        line("ORG:${escapeText(c.org.orEmpty())}$unit")
    }
    c.title.ifPresent { line("TITLE:${escapeText(it)}") }
    c.emails.filter { it.value.isNotBlank() }.forEach { line("EMAIL${typeParam(it.label)}:${escapeText(it.value)}") }
    c.phones.filter { it.value.isNotBlank() }.forEach { line("TEL${typeParam(phoneType(it.label))}:${escapeText(it.value)}") }
    c.addresses.forEach { a ->
        val parts = listOf("", "", a.street, a.city, a.region, a.postalCode, a.country)
        if (parts.any { !it.isNullOrBlank() }) {
            line("ADR${typeParam(a.label)}:" + parts.joinToString(";") { escapeText(it.orEmpty()) })
        }
    }
    c.websites.filter { it.value.isNotBlank() }.forEach { line("URL${typeParam(it.label)}:${stripControls(it.value)}") }
    c.birthday?.takeIf { ISO_DATE.matches(it) }?.let {
        line("BDAY:" + if (version == VCardVersion.V4) it.replace("-", "") else it)
    }
    c.notes.ifPresent { line("NOTE:${escapeText(it)}") }
    line("END:VCARD")
}

private inline fun String?.ifPresent(block: (String) -> Unit) {
    if (!isNullOrBlank()) block(this)
}

private fun phoneType(label: String?): String? = when (label?.trim()?.lowercase()) {
    "mobile" -> "cell"
    "work fax" -> "work,fax"
    "home fax" -> "home,fax"
    else -> label
}

/** A free-text label becomes one TYPE value, quoted when it holds a parameter delimiter. */
private fun typeParam(label: String?): String {
    val clean = stripControls(label.orEmpty()).replace("\"", "").trim().lowercase()
    if (clean.isEmpty()) return ""
    val bare = clean.all { it.isLetterOrDigit() || it == '-' || it == ',' }
    return if (bare) ";TYPE=$clean" else ";TYPE=\"$clean\""
}

private fun stripControls(s: String): String = s.filter { it >= ' ' && it != '\u007f' }

private fun escapeText(s: String): String = buildString {
    val text = s.replace("\r\n", "\n").replace('\r', '\n')
    for (ch in text) {
        when (ch) {
            '\\' -> append("\\\\")
            ',' -> append("\\,")
            ';' -> append("\\;")
            '\n' -> append("\\n")
            else -> if (ch >= ' ' && ch != '\u007f') append(ch)
        }
    }
}

/** Folds at 75 octets (RFC 6350 §3.2) on code point boundaries, CRLF-terminated. */
private fun StringBuilder.line(content: String) {
    var octets = 0
    var i = 0
    while (i < content.length) {
        val cp = content.codePointAt(i)
        val size = when {
            cp < 0x80 -> 1
            cp < 0x800 -> 2
            cp < 0x10000 -> 3
            else -> 4
        }
        if (octets + size > 75) {
            append("\r\n ")
            octets = 1
        }
        appendCodePoint(cp)
        octets += size
        i += Character.charCount(cp)
    }
    append("\r\n")
}
