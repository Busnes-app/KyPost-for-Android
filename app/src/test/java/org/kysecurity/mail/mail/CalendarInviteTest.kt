package org.kysecurity.mail.mail

import org.junit.Test
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CalendarInviteTest {

    private val berlin = ZoneId.of("Europe/Berlin")

    private fun ics(vararg lines: String) = lines.joinToString("\r\n", postfix = "\r\n").toByteArray()

    private fun invite(method: String = "REQUEST", vararg event: String) = ics(
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "METHOD:$method",
        "BEGIN:VEVENT",
        *event,
        "END:VEVENT",
        "END:VCALENDAR",
    )

    private fun parse(bytes: ByteArray, windows: (String) -> String? = { null }) =
        parseCalendarInvite(bytes, berlin, windows)

    @Test
    fun readsAGoogleStyleRequest() {
        val parsed = assertNotNull(
            parse(
                invite(
                    "REQUEST",
                    "UID:abc@google.com",
                    "SEQUENCE:0",
                    "DTSTART:20261012T130000Z",
                    "DTEND:20261012T140000Z",
                    "SUMMARY:Planning\\, Q4",
                    "LOCATION:Room 4\\; Floor 2",
                    "DESCRIPTION:Line one\\nLine two\\\\done",
                    "ORGANIZER;CN=\"Boss: The Real One\":mailto:boss@example.com",
                ),
            ),
        )
        val event = parsed.primary
        assertEquals("REQUEST", parsed.method)
        assertEquals("abc@google.com", event.uid)
        assertEquals("Planning, Q4", event.summary)
        assertEquals("Room 4; Floor 2", event.location)
        assertEquals("Line one\nLine two\\done", event.description)
        assertEquals("boss@example.com", event.organizer)
        assertEquals(Instant.parse("2026-10-12T13:00:00Z"), event.begin)
        assertEquals(Instant.parse("2026-10-12T14:00:00Z"), event.end)
        assertFalse(event.allDay)
        assertTrue(parsed.offersAdd)
        assertFalse(parsed.isUpdate)
    }

    @Test
    fun tzidIsResolvedToItsZoneNotTheDevices() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;TZID=America/New_York:20261012T090000", "DURATION:PT90M")),
        ).primary
        assertEquals(Instant.parse("2026-10-12T13:00:00Z"), event.begin)
        assertEquals(Instant.parse("2026-10-12T14:30:00Z"), event.end)
        assertNull(event.unknownZone)
    }

    @Test
    fun mozillaPrefixedTzidResolvesFromItsTail() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;TZID=/mozilla.org/20050126_1/America/New_York:20261012T090000")),
        ).primary
        assertEquals(Instant.parse("2026-10-12T13:00:00Z"), event.begin)
    }

    @Test
    fun outlookWindowsZoneGoesThroughTheTable() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;TZID=\"Pacific Standard Time\":20261012T090000")) {
                if (it == "Pacific Standard Time") "America/Los_Angeles" else null
            },
        ).primary
        assertEquals(Instant.parse("2026-10-12T16:00:00Z"), event.begin)
        assertNull(event.unknownZone)
    }

    @Test
    fun unknownTzidFallsBackToFloatingAndSaysSo() {
        val event = assertNotNull(parse(invite("REQUEST", "DTSTART;TZID=Narnia Time:20261012T090000"))).primary
        assertEquals(Instant.parse("2026-10-12T07:00:00Z"), event.begin)
        assertEquals("Narnia Time", event.unknownZone)
    }

    @Test(timeout = 5_000)
    fun hugeTzidIsUnknownNotQuadratic() {
        val tzid = "/a".repeat(100_000)
        val event = assertNotNull(parse(invite("REQUEST", "DTSTART;TZID=$tzid:20261012T090000"))).primary
        assertEquals(64, event.unknownZone?.length)
    }

    @Test
    fun foldSplittingAUtf8SequenceIsRejoined() {
        val e = "é".toByteArray()
        val bytes = "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261012T100000Z\r\nSUMMARY:Caf".toByteArray() +
            e[0] + "\r\n ".toByteArray() + e[1] + "\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n".toByteArray()
        assertEquals("Café", assertNotNull(parse(bytes)).primary.summary)
    }

    @Test
    fun impossibleDateIsRefusedNotRounded() {
        assertNull(parse(invite("REQUEST", "DTSTART:20260231T100000Z")))
        assertNull(parse(invite("REQUEST", "DTSTART;VALUE=DATE:20260231")))
    }

    @Test
    fun parameterNameCannotSwallowTheValue() {
        assertNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", "X-JUNK;FOO:a=b:c")))
    }

    @Test
    fun formatCharactersAreStrippedButJoinersKept() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "SUMMARY:a\u200Bb\u061Cc\uFEFFd \uD83D\uDC69\u200D\uD83D\uDCBB")),
        ).primary
        assertEquals("abcd \uD83D\uDC69\u200D\uD83D\uDCBB", event.summary)
        val zeroWidth = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "ORGANIZER:mailto:ce\u200Bo@example.com")),
        ).primary
        assertEquals("", zeroWidth.organizer)
    }

    @Test
    fun oneUnparseableEventRefusesTheWholeInvite() {
        val bytes = ics(
            "BEGIN:VCALENDAR",
            "METHOD:REQUEST",
            "BEGIN:VEVENT",
            "SUMMARY:no start",
            "END:VEVENT",
            "BEGIN:VEVENT",
            "DTSTART:20261012T100000Z",
            "SUMMARY:valid",
            "END:VEVENT",
            "END:VCALENDAR",
        )
        assertNull(parse(bytes))
        assertNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", "DTEND:garbage")))
    }

    @Test
    fun unknownZoneOnTheEndIsReportedToo() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;TZID=Europe/Berlin:20261012T090000", "DTEND;TZID=Narnia:20261012T100000")),
        ).primary
        assertEquals("Narnia", event.unknownZone)
    }

    @Test
    fun floatingTimeIsReadInTheLocalZone() {
        val event = assertNotNull(parse(invite("REQUEST", "DTSTART:20261012T090000"))).primary
        assertEquals(Instant.parse("2026-10-12T07:00:00Z"), event.begin)
        // No DTEND or DURATION on a DATE-TIME start: zero length, not a guessed hour.
        assertEquals(event.begin, event.end)
    }

    @Test
    fun allDayEventIsLocalMidnightWithAnExclusiveEnd() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;VALUE=DATE:20261012", "DTEND;VALUE=DATE:20261014")),
        ).primary
        assertTrue(event.allDay)
        assertEquals(Instant.parse("2026-10-11T22:00:00Z"), event.begin)
        assertEquals(Instant.parse("2026-10-13T22:00:00Z"), event.end)
    }

    @Test
    fun allDayWithoutAnEndLastsOneDay() {
        val event = assertNotNull(parse(invite("REQUEST", "DTSTART;VALUE=DATE:20261012"))).primary
        assertEquals(Instant.parse("2026-10-12T22:00:00Z"), event.end)
    }

    @Test
    fun durationDaysAreNominalAcrossDst() {
        // Berlin leaves DST on 2026-10-25: one calendar day there is 25 hours.
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART;TZID=Europe/Berlin:20261024T100000", "DURATION:P1D")),
        ).primary
        assertEquals(Instant.parse("2026-10-25T09:00:00Z"), event.end)
    }

    @Test
    fun weekDurationIsUnderstood() {
        val event = assertNotNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", "DURATION:P1W"))).primary
        assertEquals(Instant.parse("2026-10-19T10:00:00Z"), event.end)
    }

    @Test
    fun rrulePassesThroughAndJunkDoesNot() {
        val weekly = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "RRULE:FREQ=WEEKLY;BYDAY=MO;COUNT=10")),
        ).primary
        assertEquals("FREQ=WEEKLY;BYDAY=MO;COUNT=10", weekly.rrule)
        val junk = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "RRULE:FREQ=WEEKLY<script>")),
        ).primary
        assertEquals("", junk.rrule)
    }

    @Test
    fun cancelIsRecognisedAndOffersNoAdd() {
        val parsed = assertNotNull(parse(invite("CANCEL", "DTSTART:20261012T100000Z", "SEQUENCE:2")))
        assertTrue(parsed.isCancelled)
        assertFalse(parsed.isUpdate)
        assertFalse(parsed.offersAdd)
    }

    @Test
    fun raisedSequenceOnARequestIsAnUpdate() {
        val parsed = assertNotNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", "SEQUENCE:3")))
        assertTrue(parsed.isUpdate)
        assertEquals(3, parsed.primary.sequence)
    }

    @Test
    fun foldedLinesAreUnfolded() {
        val event = assertNotNull(
            parse(
                invite(
                    "REQUEST",
                    "DTSTART:20261012T100000Z",
                    "SUMMARY:A very long",
                    "  title that folds",
                    "DESCRIPTION:tab\r\n\tfolded",
                ),
            ),
        ).primary
        assertEquals("A very long title that folds", event.summary)
        assertEquals("tabfolded", event.description)
    }

    @Test
    fun alarmPropertiesDoNotOverrideTheEvents() {
        val event = assertNotNull(
            parse(
                invite(
                    "REQUEST",
                    "DTSTART:20261012T100000Z",
                    "BEGIN:VALARM",
                    "ACTION:DISPLAY",
                    "DESCRIPTION:Reminder text",
                    "END:VALARM",
                    "DESCRIPTION:The real one",
                ),
            ),
        ).primary
        assertEquals("The real one", event.description)
    }

    @Test
    fun seriesMasterIsPrimaryEvenWhenAnOverrideComesFirst() {
        val parsed = assertNotNull(
            parse(
                ics(
                    "BEGIN:VCALENDAR",
                    "METHOD:REQUEST",
                    "BEGIN:VEVENT",
                    "RECURRENCE-ID:20261019T100000Z",
                    "DTSTART:20261019T110000Z",
                    "SUMMARY:Moved instance",
                    "END:VEVENT",
                    "BEGIN:VEVENT",
                    "DTSTART:20261012T100000Z",
                    "SUMMARY:Weekly",
                    "END:VEVENT",
                    "END:VCALENDAR",
                ),
            ),
        )
        assertEquals("Weekly", parsed.primary.summary)
        assertEquals(2, parsed.events.size)
    }

    @Test
    fun organizerKeepsTheAddressAndRejectsJunk() {
        val noMailto = assertNotNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", "ORGANIZER:a@b.example"))).primary
        assertEquals("a@b.example", noMailto.organizer)
        val spoof = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "ORGANIZER:mailto:evil@x\u202Eelpmaxe.com")),
        ).primary
        assertEquals("", spoof.organizer)
    }

    @Test
    fun bidiAndControlCharactersAreStrippedFromText() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "SUMMARY:Pay\u202Egnp.exe\u0007 now")),
        ).primary
        assertEquals("Paygnp.exe now", event.summary)
    }

    @Test
    fun missingMethodIsBlankAndStillAddable() {
        val parsed = assertNotNull(
            parse(ics("BEGIN:VCALENDAR", "BEGIN:VEVENT", "DTSTART:20261012T100000Z", "END:VEVENT", "END:VCALENDAR")),
        )
        assertEquals("", parsed.method)
        assertTrue(parsed.offersAdd)
    }

    @Test
    fun malformedInputIsRefusedNotThrown() {
        val cases = listOf(
            "",
            "not a calendar at all",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261012T100000Z\r\nEND:VEVENT\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261012T100000Z\r\nEND:VTODO\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261399T100000Z\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART;TZID=\"open:20261012T100000\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:no start\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nEND:VCALENDAR\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VCALENDAR\r\nEND:VCALENDAR\r\nEND:VCALENDAR\r\n",
            "BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nDTSTART:20261012T100000Z\r\nDURATION:P\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        )
        cases.forEach { case ->
            val parsed = parseCalendarInvite(case.toByteArray(), berlin)
            // An empty DURATION is ignored, not fatal; every other case refuses the whole invite.
            if ("DURATION:P\r" in case) {
                assertEquals(assertNotNull(parsed).primary.begin, parsed.primary.end)
            } else {
                assertNull(parsed, case)
            }
        }
    }

    @Test
    fun oversizeInputIsRefusedBeforeParsing() {
        val padding = "X-PAD:" + "a".repeat(MAX_INVITE_BYTES)
        assertNull(parse(invite("REQUEST", "DTSTART:20261012T100000Z", padding)))
    }

    @Test
    fun moreThanFiftyEventsIsRefused() {
        fun events(n: Int) = (1..n).flatMap { listOf("BEGIN:VEVENT", "DTSTART:20261012T100000Z", "END:VEVENT") }
        val fifty = ics("BEGIN:VCALENDAR", *events(MAX_INVITE_EVENTS).toTypedArray(), "END:VCALENDAR")
        val fiftyOne = ics("BEGIN:VCALENDAR", *events(MAX_INVITE_EVENTS + 1).toTypedArray(), "END:VCALENDAR")
        assertEquals(MAX_INVITE_EVENTS, assertNotNull(parse(fifty)).events.size)
        assertNull(parse(fiftyOne))
    }

    @Test
    fun descriptionIsBoundedForTheBinder() {
        val event = assertNotNull(
            parse(invite("REQUEST", "DTSTART:20261012T100000Z", "DESCRIPTION:" + "d".repeat(MAX_DESCRIPTION_CHARS + 50))),
        ).primary
        assertEquals(MAX_DESCRIPTION_CHARS, event.description.length)
    }

    @Test
    fun inviteAttachmentPrefersTheCalendarPartAndRespectsTheCap() {
        val pdf = AttachmentInfo(0, "agenda.pdf", "application/pdf", 10)
        val ics = AttachmentInfo(1, "invite.ics", "application/ics", 900)
        val part = AttachmentInfo(2, "invite.ics", "text/calendar; method=REQUEST", 900)
        assertEquals(part, inviteAttachment(listOf(pdf, ics, part)))
        assertEquals(ics, inviteAttachment(listOf(pdf, ics)))
        assertNull(inviteAttachment(listOf(pdf)))
        assertNull(inviteAttachment(listOf(part.copy(size = MAX_INVITE_BYTES + 1))))
        assertNull(inviteAttachment(listOf(part.copy(size = 0))))
    }
}
