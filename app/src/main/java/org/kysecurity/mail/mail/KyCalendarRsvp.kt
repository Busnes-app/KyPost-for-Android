package org.kysecurity.mail.mail

import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** `POST /api/calendar/rsvp` body (KyPost-Server docs/NATIVE-RSVP.md). Never carries the ics:
 *  the server reads the invitation from the message itself. Always the series master. */
@Serializable
internal data class CalendarRsvpRequestDto(val messageId: String, val mailbox: String, val index: Int, val partstat: String)

/** What the answer through KyCalendar means for the client (NATIVE-RSVP.md, step 1). */
sealed interface CalendarAnswer {
    /** 200 `answered`. No mail is sent. */
    data object Answered : CalendarAnswer

    /** `kycalendar_off` or `no_event`: answer by mail instead, after the user confirms. */
    data class ByMail(val noEvent: Boolean) : CalendarAnswer

    /** 409 `conflict`: the event changed since this invitation. */
    data object Conflict : CalendarAnswer

    /** Anything else: show [message], re-enable the buttons, send no mail. */
    data class Failed(val message: String) : CalendarAnswer
}

internal const val KYCALENDAR_UNREACHABLE = "KyCalendar could not be reached; try again."
internal const val KYCALENDAR_NOT_CONFIRMED = "KyCalendar did not confirm the answer; try again."
private const val MAX_ERROR_CHARS = 200

/** Maps one `/api/calendar/rsvp` response. [body] is server text and is never logged. */
fun calendarAnswer(code: Int, body: String): CalendarAnswer {
    val reply = runCatching { Json.parseToJsonElement(body) as? JsonObject }.getOrNull()
    fun field(name: String) = (reply?.get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
    if (code == 200) {
        return if (field("outcome") == "answered") CalendarAnswer.Answered else CalendarAnswer.Failed(KYCALENDAR_NOT_CONFIRMED)
    }
    when (field("code")) {
        "kycalendar_off" -> return CalendarAnswer.ByMail(noEvent = false)
        "no_event" -> return CalendarAnswer.ByMail(noEvent = true)
        "conflict" -> return CalendarAnswer.Conflict
    }
    // Deviation from NATIVE-RSVP.md: a bare 404 (no JSON) is a relay that predates the route, so
    // KyCalendar is not in use for it. Still mailed only after the same confirmation.
    if (code == 404 && reply == null) return CalendarAnswer.ByMail(noEvent = false)
    val shown = field("error")?.filterNot { it.isISOControl() || Character.getType(it) == Character.FORMAT.toInt() }
        ?.trim()?.take(MAX_ERROR_CHARS)
    return CalendarAnswer.Failed(shown?.ifEmpty { null } ?: KYCALENDAR_UNREACHABLE)
}
