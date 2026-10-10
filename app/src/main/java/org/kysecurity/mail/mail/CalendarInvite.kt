package org.kysecurity.mail.mail

import java.time.DateTimeException
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneId
import java.time.ZoneOffset
import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Locale

/** Sender-controlled input: an invite past either bound is refused whole, before any parsing. */
const val MAX_INVITE_BYTES = 256 * 1024
const val MAX_INVITE_EVENTS = 50

/** One VEVENT. All-day events carry midnight in the zone they were parsed for, end exclusive. */
class CalendarEvent(
    /** Verbatim, for the REPLY; blank when missing or unusable. */
    val uid: String,
    val sequence: Int,
    val summary: String,
    val location: String,
    val description: String,
    /** The bare address from `mailto:`; never the sender-chosen CN. Blank when unusable. */
    val organizer: String,
    val begin: Instant,
    val end: Instant,
    val allDay: Boolean,
    val rrule: String,
    /** A TZID that resolved to nothing, so the floating-time fallback was used. */
    val unknownZone: String?,
    /** Bare addresses of every ATTENDEE that has a usable one. */
    val attendees: List<String> = emptyList(),
    /** An override's RECURRENCE-ID line restated without TZID, or null for a whole series. */
    val recurrenceId: String? = null,
    /** An iTIP REPLY needs a UID, an organizer, and a RECURRENCE-ID copied whole if there is one. */
    val canReply: Boolean = false,
) {
    /** Redacted: the description is message content. */
    override fun toString(): String = "CalendarEvent(redacted)"
}

class CalendarInvite(
    /** Uppercase iTIP METHOD, or blank when absent or not a plain token. */
    val method: String,
    val events: List<CalendarEvent>,
) {
    /** The series master when there is one; an override-only invite heads with its first override. */
    val primary: CalendarEvent get() = events.first()

    val isCancelled: Boolean get() = method == "CANCEL"

    /** A REQUEST with a raised SEQUENCE re-sends an invite the user may already have. */
    val isUpdate: Boolean get() = method == "REQUEST" && primary.sequence > 0

    /** Handing off a cancellation or someone's reply would add an event that is not happening. */
    val offersAdd: Boolean get() = method == "REQUEST" || method == "PUBLISH" || method.isBlank()

    /** [listedMethod] is the relay's `calendarMethod` for the part (KyPost-Server #353). A relay
     *  without it predates `calendarReply` (#354), ignores the field, and would deliver the RSVP
     *  as plain mail, so it gets no buttons at all. */
    fun offersRsvp(listedMethod: String): Boolean = method == "REQUEST" && primary.canReply && listedMethod.isNotEmpty()
}

/** The listed part to download, or null. A text/calendar part (the iMIP body part) beats the
 *  `.ics` file Google attaches beside it; both hold the same event. */
fun inviteAttachment(infos: List<AttachmentInfo>): AttachmentInfo? {
    fun type(info: AttachmentInfo) = info.mimeType.substringBefore(';').trim().lowercase()
    val candidate = infos.firstOrNull { type(it) == "text/calendar" }
        ?: infos.firstOrNull { type(it) == "application/ics" || it.name.trim().endsWith(".ics", ignoreCase = true) }
    return candidate?.takeIf { it.size in 1..MAX_INVITE_BYTES }
}

/** Parses the subset of RFC 5545 an invite card needs. Null on anything it cannot vouch for.
 *
 *  Floating times and all-day dates are read in [localZone]. [windowsZone] maps an Outlook TZID
 *  such as "Pacific Standard Time" to an IANA id; the JVM has no table for those. */
fun parseCalendarInvite(
    bytes: ByteArray,
    localZone: ZoneId,
    windowsZone: (String) -> String? = { null },
): CalendarInvite? {
    if (bytes.isEmpty() || bytes.size > MAX_INVITE_BYTES) return null
    return try {
        parse(String(unfold(bytes), Charsets.UTF_8).removePrefix("\uFEFF"), localZone, windowsZone)
    } catch (_: RuntimeException) {
        null
    }
}

/** RFC 5545 §3.1: unfolded as bytes, because a fold may split a UTF-8 sequence. */
private fun unfold(bytes: ByteArray): ByteArray {
    val out = java.io.ByteArrayOutputStream(bytes.size)
    var i = 0
    while (i < bytes.size) {
        val lf = when {
            bytes[i] == LF -> i
            bytes[i] == CR && i + 1 < bytes.size && bytes[i + 1] == LF -> i + 1
            else -> -1
        }
        if (lf >= 0 && lf + 1 < bytes.size && (bytes[lf + 1] == SPACE || bytes[lf + 1] == TAB)) {
            i = lf + 2
            continue
        }
        out.write(bytes[i].toInt())
        i++
    }
    return out.toByteArray()
}

private class ContentLine(val name: String, val params: Map<String, String>, val value: String)

private fun parse(text: String, localZone: ZoneId, windowsZone: (String) -> String?): CalendarInvite? {
    val lines = text.replace("\r\n", "\n").replace('\r', '\n')
        .split('\n')
        .filter { it.isNotBlank() }
    val stack = ArrayList<String>()
    var method = ""
    var event: MutableMap<String, ContentLine>? = null
    val attendees = ArrayList<String>()
    val events = ArrayList<Parsed>()
    var eventCount = 0
    for ((index, raw) in lines.withIndex()) {
        val line = contentLine(raw) ?: return null
        if (index == 0 && !(line.name == "BEGIN" && line.value.equals("VCALENDAR", ignoreCase = true))) return null
        if (index > 0 && stack.isEmpty()) return null
        when (line.name) {
            "BEGIN" -> {
                val component = line.value.trim().uppercase()
                if (component == "VCALENDAR" && stack.isNotEmpty()) return null
                if (component == "VEVENT") {
                    if (stack.size != 1 || ++eventCount > MAX_INVITE_EVENTS) return null
                    event = HashMap()
                    attendees.clear()
                }
                stack.add(component)
            }
            "END" -> {
                if (stack.lastOrNull() != line.value.trim().uppercase()) return null
                if (stack.removeAt(stack.size - 1) == "VEVENT") {
                    event?.let { toEvent(it, attendees.toList(), localZone, windowsZone) }?.let(events::add)
                    event = null
                }
            }
            else -> when {
                stack.size == 1 && line.name == "METHOD" ->
                    method = line.value.trim().uppercase().takeIf { METHOD_TOKEN.matches(it) }.orEmpty()
                // Only the VEVENT's own properties: a VALARM inside it has a DESCRIPTION too.
                stack.size == 2 && stack[1] == "VEVENT" && line.name == "ATTENDEE" ->
                    mailtoAddress(line.value)?.takeIf { attendees.size < MAX_ATTENDEES }?.let(attendees::add)
                stack.size == 2 && stack[1] == "VEVENT" -> event?.putIfAbsent(line.name, line)
            }
        }
    }
    if (stack.isNotEmpty() || events.isEmpty()) return null
    val ordered = events.sortedBy { it.isOverride }
    return CalendarInvite(method, ordered.map { it.event })
}

private class Parsed(val event: CalendarEvent, val isOverride: Boolean)

private fun toEvent(
    props: Map<String, ContentLine>,
    attendees: List<String>,
    localZone: ZoneId,
    windowsZone: (String) -> String?,
): Parsed? {
    val start = props["DTSTART"]?.let { time(it, localZone, windowsZone) } ?: return null
    val end = props["DTEND"]?.let { time(it, localZone, windowsZone) }?.at
        ?: props["DURATION"]?.let { addDuration(start.at, it.value.trim()) }
        ?: if (start.allDay) start.at.plusDays(1) else start.at
    val uid = props["UID"]?.value?.trim()?.takeIf { it.length <= 1_000 && it.none(Char::isISOControl) }.orEmpty()
    val organizer = props["ORGANIZER"]?.value?.let(::mailtoAddress).orEmpty()
    val recurrence = props["RECURRENCE-ID"]
    val recurrenceId = recurrence?.let { recurrenceIdLine(it, localZone, windowsZone) }
    // A SEQUENCE we cannot read back exactly would make a valid-looking reply to the wrong revision.
    val sequence = props["SEQUENCE"]?.value?.trim().let { if (it == null) 0 else it.toIntOrNull()?.takeIf { n -> n >= 0 } }
    return Parsed(
        CalendarEvent(
            uid = uid,
            sequence = sequence ?: 0,
            summary = text(props["SUMMARY"], 1_000),
            location = text(props["LOCATION"], 1_000),
            description = text(props["DESCRIPTION"], MAX_DESCRIPTION_CHARS),
            organizer = organizer,
            begin = start.at.toInstant(),
            end = maxOf(end, start.at).toInstant(),
            allDay = start.allDay,
            rrule = props["RRULE"]?.value?.trim()?.takeIf { RRULE_SAFE.matches(it) }.orEmpty(),
            unknownZone = start.unknownZone,
            attendees = attendees,
            recurrenceId = recurrenceId,
            canReply = uid.isNotEmpty() && organizer.isNotEmpty() && sequence != null &&
                (recurrence == null || recurrenceId != null),
        ),
        isOverride = props.containsKey("RECURRENCE-ID"),
    )
}

/** The REPLY carries no VTIMEZONE, so a TZID cannot be copied: a date stays a date, a floating or
 *  UTC time stays as written, a zoned time becomes UTC. Null when it cannot be restated. */
private fun recurrenceIdLine(line: ContentLine, localZone: ZoneId, windowsZone: (String) -> String?): String? {
    val time = time(line, localZone, windowsZone)?.takeIf { it.unknownZone == null } ?: return null
    val value = line.value.trim()
    return when {
        time.allDay -> "RECURRENCE-ID;VALUE=DATE:$value"
        line.params["TZID"].isNullOrBlank() || value.endsWith("Z") -> "RECURRENCE-ID:$value"
        else -> "RECURRENCE-ID:" + DTSTAMP_FORMAT.format(time.at.withZoneSameInstant(ZoneOffset.UTC))
    }
}

private class EventTime(val at: ZonedDateTime, val allDay: Boolean, val unknownZone: String?)

private fun time(line: ContentLine, localZone: ZoneId, windowsZone: (String) -> String?): EventTime? {
    val value = line.value.trim()
    if (line.params["VALUE"].equals("DATE", ignoreCase = true) || DATE.matches(value)) {
        if (!DATE.matches(value)) return null
        return EventTime(LocalDate.parse(value, DateTimeFormatter.BASIC_ISO_DATE).atStartOfDay(localZone), true, null)
    }
    val match = DATE_TIME.matchEntire(value) ?: return null
    val local = LocalDateTime.parse(match.groupValues[1], DATE_TIME_FORMAT)
    if (match.groupValues[2].isNotEmpty()) return EventTime(local.atZone(ZoneOffset.UTC), false, null)
    val tzid = line.params["TZID"]?.trim().orEmpty()
    if (tzid.isEmpty()) return EventTime(local.atZone(localZone), false, null)
    val zone = resolveZone(tzid, windowsZone)
    return EventTime(local.atZone(zone ?: localZone), false, tzid.take(64).takeIf { zone == null })
}

/** IANA id as given, then its last two or three path segments
 *  (`/mozilla.org/20050126_1/America/New_York`), then the Windows-name table. */
private fun resolveZone(tzid: String, windowsZone: (String) -> String?): ZoneId? {
    if (tzid.length > MAX_TZID_CHARS) return null
    val segments = tzid.split('/').filter { it.isNotEmpty() }
    val candidates = listOf(tzid, segments.takeLast(3).joinToString("/"), segments.takeLast(2).joinToString("/")) +
        listOfNotNull(runCatching { windowsZone(tzid) }.getOrNull())
    return candidates.firstNotNullOfOrNull { id ->
        try {
            ZoneId.of(id)
        } catch (_: DateTimeException) {
            null
        }
    }
}

/** RFC 5545 §3.3.6. Days and weeks are nominal, so they move with DST like a calendar would. */
private fun addDuration(start: ZonedDateTime, value: String): ZonedDateTime? {
    val m = DURATION.matchEntire(value) ?: return null
    if (m.groupValues.drop(2).all { it.isEmpty() }) return null
    fun n(group: Int) = m.groupValues[group].ifEmpty { "0" }.toLong()
    val sign = if (m.groupValues[1] == "-") -1 else 1
    return start.plusWeeks(sign * n(2)).plusDays(sign * n(3))
        .plusHours(sign * n(4)).plusMinutes(sign * n(5)).plusSeconds(sign * n(6))
}

private fun mailtoAddress(value: String): String? {
    val address = value.trim().let { if (it.startsWith("mailto:", ignoreCase = true)) it.substring(7) else it }
    return address.takeIf { ADDRESS.matches(it) }
}

/** An RSVP answer and its iTIP PARTSTAT ([name]). */
enum class Rsvp(val subjectPrefix: String, val verb: String) {
    ACCEPTED("Accepted", "accepted"),
    TENTATIVE("Tentative", "tentatively accepted"),
    DECLINED("Declined", "declined"),
}

/** The user's attendee address: the one of [accountAddresses] the invite lists, else the primary.
 *  Null when no usable address is known. */
fun rsvpAttendee(event: CalendarEvent, accountAddresses: List<String>): String? {
    val own = accountAddresses.map { it.trim() }.filter { ADDRESS.matches(it) }
    return own.firstOrNull { mine -> event.attendees.any { it.equals(mine, ignoreCase = true) } } ?: own.firstOrNull()
}

/** RFC 5546 §3.2.3 REPLY: same UID, SEQUENCE and RECURRENCE-ID, this attendee's PARTSTAT, a fresh
 *  DTSTAMP, addressed to the ORGANIZER. Never encrypted: the organizer's calendar must read it. */
fun rsvpDraft(event: CalendarEvent, attendee: String, answer: Rsvp, now: Instant, sendAs: String = ""): MailDraft {
    require(event.canReply && ADDRESS.matches(attendee))
    val ics = listOfNotNull(
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//KyPost//Android//EN",
        "METHOD:REPLY",
        "BEGIN:VEVENT",
        "UID:${event.uid}",
        event.recurrenceId,
        "SEQUENCE:${event.sequence}",
        "DTSTAMP:" + DTSTAMP_FORMAT.format(now.atZone(ZoneOffset.UTC)),
        "ORGANIZER:mailto:${event.organizer}",
        "ATTENDEE;PARTSTAT=${answer.name}:mailto:$attendee",
        "END:VEVENT",
        "END:VCALENDAR",
    ).joinToString("") { fold(it) + "\r\n" }
    val title = event.summary.replace(WHITESPACE_RUN, " ").ifEmpty { "Invitation" }
    return MailDraft(
        to = event.organizer,
        subject = "${answer.subjectPrefix}: $title",
        body = "$attendee has ${answer.verb} this invitation.",
        mode = "plain",
        from = sendAs,
        calendarReply = ics,
    )
}

/** True when the relay answered and refused: nothing went out, so asking again is safe. Anything
 *  else (a timeout, a 502) may have been sent. */
fun MailOutcome<*>.refusedBeforeSending(): Boolean = when (this) {
    is MailOutcome.BadRequest,
    is MailOutcome.NotConfigured,
    is MailOutcome.Unauthorized,
    is MailOutcome.ServiceUnavailable,
    is MailOutcome.CertificateMismatch,
    is MailOutcome.ClientSideNeeded,
    is MailOutcome.RateLimited,
    -> true
    else -> false
}

/** RFC 5545 §3.1: at most 75 octets a line, never splitting a UTF-8 sequence. */
private fun fold(line: String): String {
    val out = StringBuilder(line.length + line.length / 70 * 3)
    var octets = 0
    var i = 0
    while (i < line.length) {
        val cp = line.codePointAt(i)
        val size = when {
            cp < 0x80 -> 1
            cp < 0x800 -> 2
            cp < 0x10000 -> 3
            else -> 4
        }
        if (octets + size > 75) {
            out.append("\r\n ")
            octets = 1
        }
        out.appendCodePoint(cp)
        octets += size
        i += Character.charCount(cp)
    }
    return out.toString()
}

/** RFC 5545 §3.3.11 unescape, then strip what could reorder or hide text on the card. */
private fun text(line: ContentLine?, limit: Int): String {
    val value = line?.value ?: return ""
    val out = StringBuilder(minOf(value.length, limit))
    var i = 0
    while (i < value.length && out.length < limit) {
        var c = value[i++]
        if (c == '\\' && i < value.length) {
            c = value[i++].let { if (it == 'n' || it == 'N') '\n' else it }
        }
        if (c == '\n' || c == '\t' || c == ZWJ || !(c.isISOControl() || Character.getType(c) == Character.FORMAT.toInt())) {
            out.append(c)
        }
    }
    return out.toString().trim()
}

/** `NAME *(;PARAM=value) : value`, with quoted parameter values that may hold `:` or `;`. */
private fun contentLine(line: String): ContentLine? {
    var i = 0
    while (i < line.length && line[i] != ';' && line[i] != ':') i++
    if (i == line.length || i == 0) return null
    val name = line.substring(0, i).uppercase()
    if (!NAME.matches(name)) return null
    val params = HashMap<String, String>()
    while (line[i] == ';') {
        val eq = line.indexOf('=', i)
        if (eq < 0) return null
        val param = line.substring(i + 1, eq).uppercase()
        if (!NAME.matches(param)) return null
        i = eq + 1
        val value = StringBuilder()
        while (i < line.length && line[i] != ';' && line[i] != ':') {
            if (line[i] == '"') {
                val close = line.indexOf('"', i + 1)
                if (close < 0) return null
                value.append(line, i + 1, close)
                i = close + 1
            } else {
                value.append(line[i++])
            }
        }
        if (i == line.length) return null
        params.putIfAbsent(param, value.toString())
    }
    return ContentLine(name, params, line.substring(i + 1))
}

/** Bounds both the card and the insert Intent, which crosses Binder's ~1 MB transaction limit. */
const val MAX_DESCRIPTION_CHARS = 16_000

private const val CR = '\r'.code.toByte()
private const val LF = '\n'.code.toByte()
private const val SPACE = ' '.code.toByte()
private const val TAB = '\t'.code.toByte()
private const val ZWJ = '\u200D'
private const val MAX_TZID_CHARS = 128
private const val MAX_ATTENDEES = 500
private val WHITESPACE_RUN = Regex("\\s+")
private val DTSTAMP_FORMAT = DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss'Z'", Locale.ROOT)
private val NAME = Regex("[A-Z0-9-]{1,64}")
private val METHOD_TOKEN = Regex("[A-Z][A-Z0-9-]{0,31}")
private val DATE = Regex("\\d{8}")
private val DATE_TIME = Regex("(\\d{8}T\\d{6})(Z?)")
private val DATE_TIME_FORMAT = DateTimeFormatter.ofPattern("uuuuMMdd'T'HHmmss").withResolverStyle(ResolverStyle.STRICT)
private val DURATION = Regex("([+-]?)P(?:(\\d{1,6})W|(?:(\\d{1,6})D)?(?:T(?:(\\d{1,6})H)?(?:(\\d{1,6})M)?(?:(\\d{1,6})S)?)?)")
private val RRULE_SAFE = Regex("[A-Za-z0-9=;,:+\\-]{1,512}")
private val ADDRESS = Regex("[^\\s@<>\"\\p{Cntrl}\\p{Cf}]{1,64}@[^\\s@<>\"\\p{Cntrl}\\p{Cf}]{1,190}")
