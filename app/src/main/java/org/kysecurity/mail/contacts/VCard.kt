package org.kysecurity.mail.contacts

import org.kysecurity.mail.AttachmentTooLargeException
import org.kysecurity.mail.readAtMost
import java.io.InputStream
import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.time.LocalDate

const val VCARD_MIME_TYPE = "text/vcard"

enum class VCardVersion(val number: String) { V4("4.0"), V3("3.0") }

/** YYYY-MM-DD that is a real date: `2025-02-29`, `2026-13-01` and `+10000-01-01` are refused. */
private fun isCalendarDate(s: String): Boolean = s.length == 10 && runCatching { LocalDate.parse(s) }.isSuccess

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
    c.phones.filter { it.value.isNotBlank() }.forEach { line("TEL${phoneTypeParam(it.label)}:${escapeText(it.value)}") }
    c.addresses.forEach { a ->
        val parts = listOf("", "", a.street, a.city, a.region, a.postalCode, a.country)
        if (parts.any { !it.isNullOrBlank() }) {
            line("ADR${typeParam(a.label)}:" + parts.joinToString(";") { escapeText(it.orEmpty()) })
        }
    }
    c.websites.filter { it.value.isNotBlank() }.forEach { line("URL${typeParam(it.label)}:${stripControls(it.value)}") }
    c.birthday?.takeIf(::isCalendarDate)?.let {
        line("BDAY:" + if (version == VCardVersion.V4) it.replace("-", "") else it)
    }
    c.notes.ifPresent { line("NOTE:${escapeText(it)}") }
    line("END:VCARD")
}

private inline fun String?.ifPresent(block: (String) -> Unit) {
    if (!isNullOrBlank()) block(this)
}

/** The fax labels map to two TYPE tokens on purpose; everything else is one free-text value. */
private fun phoneTypeParam(label: String?): String = when (label?.trim()?.lowercase()) {
    "mobile" -> ";TYPE=cell"
    "work fax" -> ";TYPE=work,fax"
    "home fax" -> ";TYPE=home,fax"
    else -> typeParam(label)
}

/** A free-text label becomes one TYPE value, quoted when it holds a parameter delimiter. */
private fun typeParam(label: String?): String {
    val clean = stripControls(label.orEmpty()).replace("\"", "").trim().lowercase()
    if (clean.isEmpty()) return ""
    val bare = clean.all { it.isLetterOrDigit() || it == '-' }
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

const val MAX_VCARD_IMPORT_BYTES = 256L * 1024
const val MAX_VCARD_IMPORT_CONTACTS = 200

/** KyPost-Server's `maxValuesPerField`; it truncates past this, so refuse rather than diverge. */
const val MAX_VCARD_VALUES_PER_FIELD = 64

sealed class VCardImport {
    data class Parsed(val contacts: List<ContactDto>, val skipped: Int) : VCardImport()
    data class Refused(val reason: Refusal) : VCardImport()

    enum class Refusal { TOO_LARGE, NOT_UTF8, MALFORMED, UNSUPPORTED_VERSION, TOO_MANY_CONTACTS, TOO_MANY_VALUES, EMPTY }
}

fun readVCardImport(input: InputStream): VCardImport = try {
    parseVCards(readAtMost(input, MAX_VCARD_IMPORT_BYTES))
} catch (_: AttachmentTooLargeException) {
    VCardImport.Refused(VCardImport.Refusal.TOO_LARGE)
}

/** Strict reader for hostile files: vCard 3.0/4.0 only, strict UTF-8, whole file refused on any
 *  structural error or cap. Reads only the properties [writeVCards] writes; UID, KEY, PHOTO and
 *  everything else are ignored, so a file can never pin a PGP key or choose a server uid. */
fun parseVCards(bytes: ByteArray): VCardImport = try {
    val text = Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
    parseUnfolded(text.removePrefix("\uFEFF").replace("\r\n", "\n").replace('\r', '\n').replace(FOLD, ""))
} catch (_: CharacterCodingException) {
    VCardImport.Refused(VCardImport.Refusal.NOT_UTF8)
} catch (e: RefusedVCard) {
    VCardImport.Refused(e.reason)
}

private val FOLD = Regex("\n[ \t]")
private val BASIC_DATE = Regex("""\d{8}""")
private val EXTENDED_DATE = Regex("""\d{4}-\d{2}-\d{2}(T.*)?""")
private val PROPERTY_NAME = Regex("[A-Za-z0-9-]+")
private val IGNORED_TYPES = setOf("pref", "voice", "internet", "text", "x400", "msg")

private class RefusedVCard(val reason: VCardImport.Refusal) : Exception()

private fun refuse(reason: VCardImport.Refusal): Nothing = throw RefusedVCard(reason)

private class VCardProperty(val name: String, val types: Set<String>, val encoded: Boolean, val value: String)

private fun parseUnfolded(text: String): VCardImport {
    val contacts = mutableListOf<ContactDto>()
    var skipped = 0
    var card: MutableList<VCardProperty>? = null
    for (line in text.split('\n')) {
        if (line.isBlank()) continue
        val property = parseProperty(line) ?: refuse(VCardImport.Refusal.MALFORMED)
        val open = card
        when {
            property.name == "BEGIN" && property.value.equals("VCARD", ignoreCase = true) -> {
                if (open != null) refuse(VCardImport.Refusal.MALFORMED)
                if (contacts.size + skipped >= MAX_VCARD_IMPORT_CONTACTS) refuse(VCardImport.Refusal.TOO_MANY_CONTACTS)
                card = mutableListOf()
            }
            property.name == "END" && property.value.equals("VCARD", ignoreCase = true) -> {
                val contact = toContact(open ?: refuse(VCardImport.Refusal.MALFORMED))
                if (contact == null) skipped++ else contacts += contact
                card = null
            }
            open == null -> refuse(VCardImport.Refusal.MALFORMED)
            else -> open += property
        }
    }
    if (card != null) refuse(VCardImport.Refusal.MALFORMED)
    if (contacts.isEmpty()) refuse(VCardImport.Refusal.EMPTY)
    return VCardImport.Parsed(contacts, skipped)
}

/** `group.NAME;PARAM=a,"b;c";BARE:value`; null when there is no unquoted colon. */
private fun parseProperty(line: String): VCardProperty? {
    val parts = mutableListOf<String>()
    val current = StringBuilder()
    var quoted = false
    for ((i, ch) in line.withIndex()) {
        when {
            ch == '"' -> quoted = !quoted
            ch == ';' && !quoted -> { parts += current.toString(); current.clear() }
            ch == ':' && !quoted -> {
                parts += current.toString()
                val name = parts[0].substringAfter('.')
                if (!PROPERTY_NAME.matches(name)) return null
                val types = linkedSetOf<String>()
                var encoded = false
                parts.drop(1).forEach { param ->
                    val key = param.substringBefore('=', "").uppercase()
                    val value = param.substringAfter('=')
                    when {
                        key == "ENCODING" -> encoded = true
                        key == "TYPE" || key.isEmpty() ->
                            value.split(',').map { it.trim().lowercase() }.filter { it.isNotEmpty() }.forEach { types += it }
                    }
                }
                return VCardProperty(name.uppercase(), types, encoded, line.substring(i + 1))
            }
            else -> current.append(ch)
        }
    }
    return null
}

private fun toContact(properties: List<VCardProperty>): ContactDto? {
    val version = properties.firstOrNull { it.name == "VERSION" }?.value?.trim() ?: refuse(VCardImport.Refusal.MALFORMED)
    if (version != VCardVersion.V4.number && version != VCardVersion.V3.number) refuse(VCardImport.Refusal.UNSUPPORTED_VERSION)
    val byName = properties.filterNot { it.encoded }.groupBy { it.name }
    fun all(name: String) = byName[name].orEmpty().also {
        if (it.size > MAX_VCARD_VALUES_PER_FIELD) refuse(VCardImport.Refusal.TOO_MANY_VALUES)
    }
    fun text(name: String) = byName[name]?.first()?.let { unescapeText(it.value) }?.takeIf { it.isNotBlank() }
    fun parts(name: String) = byName[name]?.first()?.let { splitComponents(it.value) }.orEmpty()
    fun List<String>.at(i: Int) = getOrNull(i)?.takeIf { it.isNotBlank() }

    val n = parts("N")
    val org = parts("ORG")
    val emails = all("EMAIL").mapNotNull { field(it) }
    val phones = all("TEL").mapNotNull { p ->
        field(p, unescapeText(p.value).trim().let { if (it.startsWith("tel:", ignoreCase = true)) it.substring(4) else it })
    }
    val addresses = all("ADR").mapNotNull { p ->
        val a = splitComponents(p.value)
        ContactAddressDto(label(p.types), a.at(2), a.at(3), a.at(4), a.at(5), a.at(6))
            .takeIf { listOf(it.street, it.city, it.region, it.postalCode, it.country).any { v -> v != null } }
    }
    val websites = all("URL").mapNotNull { p -> field(p)?.let { ContactUrlDto(it.label, it.value) } }
    val fn = text("FN")
        ?: listOfNotNull(n.at(3), n.at(1), n.at(2), n.at(0), n.at(4)).joinToString(" ").ifBlank { null }
        ?: org.at(0)
        ?: emails.firstOrNull()?.value
        ?: return null
    return ContactDto(
        fn = fn,
        familyName = n.at(0),
        givenName = n.at(1),
        middleName = n.at(2),
        prefix = n.at(3),
        suffix = n.at(4),
        nickname = text("NICKNAME"),
        org = org.at(0),
        department = org.at(1),
        title = text("TITLE"),
        emails = emails,
        phones = phones,
        addresses = addresses,
        websites = websites,
        birthday = birthday(text("BDAY")),
        notes = text("NOTE"),
    )
}

private fun field(p: VCardProperty, value: String = unescapeText(p.value).trim()) =
    value.takeIf { it.isNotEmpty() }?.let { ContactFieldDto(label(p.types), it) }

/** Inverse of [typeParam]/[phoneType] for the labels this app writes; others keep their name. */
private fun label(types: Set<String>): String? {
    val t = types - IGNORED_TYPES
    return when {
        "cell" in t -> "Mobile"
        "fax" in t && "work" in t -> "Work Fax"
        "fax" in t && "home" in t -> "Home Fax"
        "home" in t -> "Home"
        "work" in t -> "Work"
        else -> t.firstOrNull()?.replaceFirstChar { it.uppercase() }
    }
}

private fun birthday(raw: String?): String? {
    val v = raw?.trim() ?: return null
    val iso = when {
        BASIC_DATE.matches(v) -> "${v.substring(0, 4)}-${v.substring(4, 6)}-${v.substring(6, 8)}"
        EXTENDED_DATE.matches(v) -> v.substring(0, 10)
        else -> return null
    }
    return iso.takeIf(::isCalendarDate)
}

/** Splits on unescaped `;`, then unescapes each component. */
private fun splitComponents(value: String): List<String> {
    val parts = mutableListOf<String>()
    val current = StringBuilder()
    var i = 0
    while (i < value.length) {
        val ch = value[i]
        when {
            ch == '\\' && i + 1 < value.length -> { current.append(ch).append(value[i + 1]); i++ }
            ch == ';' -> { parts += unescapeText(current.toString()); current.clear() }
            else -> current.append(ch)
        }
        i++
    }
    parts += unescapeText(current.toString())
    return parts
}

/** Undoes [escapeText]; drops control characters other than newline. */
private fun unescapeText(s: String): String = buildString {
    var i = 0
    while (i < s.length) {
        var ch = s[i++]
        if (ch == '\\') {
            if (i == s.length) break
            ch = s[i++].let { if (it == 'n' || it == 'N') '\n' else it }
        }
        if ((ch >= ' ' && ch != '\u007f') || ch == '\n') append(ch)
    }
}
