package org.kysecurity.mail

import android.provider.CalendarContract
import org.junit.Test
import org.kysecurity.mail.mail.MAX_DESCRIPTION_CHARS
import org.kysecurity.mail.mail.parseCalendarInvite
import java.time.ZoneId
import java.util.Locale
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull

class CalendarHandoffTest {

    private val berlin = ZoneId.of("Europe/Berlin")

    /** CLDR 42+ puts a narrow no-break space before AM/PM. */
    private fun String.normalizeSpaces() = replace(' ', ' ')

    private fun event(vararg lines: String) = assertNotNull(
        parseCalendarInvite(
            (listOf("BEGIN:VCALENDAR", "METHOD:REQUEST", "BEGIN:VEVENT") + lines + listOf("END:VEVENT", "END:VCALENDAR"))
                .joinToString("\r\n").toByteArray(),
            berlin,
        ),
    ).primary

    @Test
    fun insertExtrasCarryEverySupportedField() {
        val extras = calendarInsertExtras(
            event(
                "DTSTART:20261012T130000Z",
                "DTEND:20261012T140000Z",
                "SUMMARY:Planning",
                "LOCATION:Room 4",
                "DESCRIPTION:Agenda",
                "RRULE:FREQ=WEEKLY;COUNT=3",
            ),
        )
        assertEquals(
            mapOf(
                "title" to "Planning",
                "beginTime" to 1_791_810_000_000L,
                "endTime" to 1_791_813_600_000L,
                "allDay" to false,
                "eventLocation" to "Room 4",
                "description" to "Agenda",
                "rrule" to "FREQ=WEEKLY;COUNT=3",
            ),
            extras,
        )
        // The keys are the platform's, not copies that could drift from them.
        assertEquals("beginTime", CalendarContract.EXTRA_EVENT_BEGIN_TIME)
    }

    @Test
    fun allDayInsertOmitsEmptyFields() {
        val extras = calendarInsertExtras(event("DTSTART;VALUE=DATE:20261012"))
        assertEquals(true, extras[CalendarContract.EXTRA_EVENT_ALL_DAY])
        assertFalse(CalendarContract.Events.EVENT_LOCATION in extras)
        assertFalse(CalendarContract.Events.DESCRIPTION in extras)
        assertFalse(CalendarContract.Events.RRULE in extras)
    }

    @Test
    fun emailEventCarriesSubjectAndBodyButNoTime() {
        val extras = emailEventExtras(
            subject = "Lunch Friday 12:30?",
            body = "<html><head><style>p{color:red}</style></head><body><p>See you</p><script>x()</script></body></html>",
            bodyMode = "html",
        )
        assertEquals("Lunch Friday 12:30?", extras[CalendarContract.Events.TITLE])
        assertEquals("See you", extras[CalendarContract.Events.DESCRIPTION])
        assertFalse(CalendarContract.EXTRA_EVENT_BEGIN_TIME in extras)
        assertFalse(CalendarContract.EXTRA_EVENT_END_TIME in extras)
    }

    @Test
    fun emailEventKeepsPlainTextAndBoundsIt() {
        val plain = emailEventExtras("s", "line <a@b.example>\n" + "x".repeat(MAX_DESCRIPTION_CHARS), "plain")
        val description = plain[CalendarContract.Events.DESCRIPTION] as String
        assertEquals(MAX_DESCRIPTION_CHARS, description.length)
        assertEquals("line <a@b.example>", description.lineSequence().first())
        assertFalse(CalendarContract.Events.DESCRIPTION in emailEventExtras("s", null, ""))
    }

    @Test
    fun whenTextIsInTheViewersZone() {
        val event = event("DTSTART:20261012T130000Z", "DTEND:20261012T140000Z")
        assertEquals("Oct 12, 2026, 3:00 PM – 4:00 PM", inviteWhenText(event, berlin, Locale.US))
        assertEquals("Oct 12, 2026, 9:00 AM – 10:00 AM", inviteWhenText(event, ZoneId.of("America/New_York"), Locale.US))
    }

    @Test
    fun allDayWhenTextShowsTheInclusiveRange() {
        assertEquals("Oct 12, 2026", inviteWhenText(event("DTSTART;VALUE=DATE:20261012"), berlin, Locale.US))
        assertEquals(
            "Oct 12, 2026 – Oct 13, 2026",
            inviteWhenText(event("DTSTART;VALUE=DATE:20261012", "DTEND;VALUE=DATE:20261014"), berlin, Locale.US),
        )
    }
}
