package org.kysecurity.mail.mail

import org.junit.Test
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class CalendarRsvpTest {

    private val now = Instant.parse("2026-10-10T08:09:10Z")

    private fun invite(vararg event: String, method: String = "REQUEST") = assertNotNull(
        parseCalendarInvite(
            (listOf("BEGIN:VCALENDAR", "METHOD:$method", "BEGIN:VEVENT") + event + listOf("END:VEVENT", "END:VCALENDAR"))
                .joinToString("\r\n").toByteArray(),
            ZoneId.of("UTC"),
        ),
    )

    private val request = arrayOf(
        "UID:040000008200E00074C5B7101A82E008@outlook.example",
        "SEQUENCE:4",
        "DTSTART:20261012T100000Z",
        "SUMMARY:Quarterly\\nplanning",
        "ORGANIZER;CN=Boss:mailto:boss@example.com",
        "ATTENDEE;PARTSTAT=NEEDS-ACTION:mailto:me@example.com",
        "ATTENDEE;CN=\"Me, Alias\";RSVP=TRUE:MAILTO:Alias@Example.com",
    )

    /** KyPost-Server's `mailmsg.CalendarReply` checks, ported: what the relay refuses with 400. */
    private fun assertRelayAccepts(ics: String) {
        assertTrue(ics.length <= 64 * 1024)
        assertTrue(ics.endsWith("\r\n"))
        val lines = ics.removeSuffix("\r\n").split("\r\n")
        assertEquals("BEGIN:VCALENDAR", lines.first())
        val stack = ArrayList<String>()
        var methods = 0
        var events = 0
        for ((index, line) in lines.withIndex()) {
            assertTrue(line.isNotEmpty(), "empty line")
            assertTrue(line.none { (it < ' ' && it != '\t') || it == '\u007f' }, "control char in $line")
            assertTrue(line.toByteArray().size <= 75, "unfolded line: $line")
            if (line[0] == ' ') continue
            assertTrue(index == 0 || stack.isNotEmpty(), "content after END:VCALENDAR")
            val name = line.substringBefore(':').substringBefore(';').uppercase()
            val value = line.substringAfter(':').trim().uppercase()
            when (name) {
                "BEGIN" -> {
                    stack.add(value)
                    if (value == "VEVENT") events++
                }
                "END" -> assertEquals(stack.removeAt(stack.size - 1), value, "unbalanced END")
                "METHOD" -> {
                    assertEquals(1, stack.size)
                    assertEquals("REPLY", value)
                    methods++
                }
            }
        }
        assertTrue(stack.isEmpty())
        assertEquals(1, methods)
        assertEquals(1, events)
    }

    private fun unfold(ics: String) = ics.replace("\r\n ", "")

    @Test
    fun replyCopiesUidAndSequenceAndAnswersAsTheListedAddress() {
        val event = invite(*request).primary
        val attendee = assertNotNull(rsvpAttendee(event, listOf("primary@example.com", "alias@example.com")))
        assertEquals("alias@example.com", attendee)

        val draft = rsvpDraft(event, attendee, Rsvp.ACCEPTED, now)
        val ics = assertNotNull(draft.calendarReply)
        assertRelayAccepts(ics)
        val lines = unfold(ics).removeSuffix("\r\n").split("\r\n")
        assertTrue("UID:040000008200E00074C5B7101A82E008@outlook.example" in lines)
        assertTrue("SEQUENCE:4" in lines)
        assertTrue("DTSTAMP:20261010T080910Z" in lines)
        assertTrue("ORGANIZER:mailto:boss@example.com" in lines)
        assertTrue("ATTENDEE;PARTSTAT=ACCEPTED:mailto:alias@example.com" in lines)
        assertFalse(lines.any { it.startsWith("RECURRENCE-ID") })

        assertEquals("boss@example.com", draft.to)
        assertEquals("Accepted: Quarterly planning", draft.subject)
        assertFalse(draft.encrypt)
        assertFalse(draft.sign)
        assertFalse(draft.allowPickupFallback)
    }

    @Test
    fun ourOwnParserReadsTheReplyBack() {
        val event = invite(*request).primary
        val reply = rsvpDraft(event, "me@example.com", Rsvp.DECLINED, now).calendarReply!!
        // The card parser insists on DTSTART, which a REPLY need not carry; add one to read it back.
        val withStart = reply.replace("END:VEVENT", "DTSTART:20261012T100000Z\r\nEND:VEVENT")
        val parsed = assertNotNull(parseCalendarInvite(withStart.toByteArray(), ZoneId.of("UTC")))
        assertEquals("REPLY", parsed.method)
        assertEquals(event.uid, parsed.primary.uid)
        assertEquals(listOf("me@example.com"), parsed.primary.attendees)
    }

    @Test
    fun eachAnswerIsItsPartstat() {
        val event = invite(*request).primary
        Rsvp.entries.forEach { answer ->
            val ics = unfold(rsvpDraft(event, "me@example.com", answer, now).calendarReply!!)
            assertTrue("ATTENDEE;PARTSTAT=${answer.name}:mailto:me@example.com" in ics, ics)
        }
    }

    @Test
    fun overrideRecurrenceIdIsRestatedWithoutATzid() {
        // The REPLY carries no VTIMEZONE, so a zoned RECURRENCE-ID must become UTC.
        fun reply(rid: String) = unfold(
            rsvpDraft(invite(*request, rid).primary, "me@example.com", Rsvp.TENTATIVE, now).calendarReply!!,
        )
        assertTrue("\r\nRECURRENCE-ID:20261019T080000Z\r\n" in reply("RECURRENCE-ID;TZID=Europe/Berlin:20261019T100000"))
        assertTrue("\r\nRECURRENCE-ID:20261019T100000Z\r\n" in reply("RECURRENCE-ID:20261019T100000Z"))
        assertTrue("\r\nRECURRENCE-ID;VALUE=DATE:20261019\r\n" in reply("RECURRENCE-ID;VALUE=DATE:20261019"))
        assertTrue("\r\nRECURRENCE-ID:20261019T100000\r\n" in reply("RECURRENCE-ID;X-JUNK=1:20261019T100000"))
    }

    @Test
    fun unrestatableRecurrenceIdOrSequenceMeansNoRsvp() {
        assertFalse(invite(*request, "RECURRENCE-ID;TZID=Narnia:20261019T100000").offersRsvp("REQUEST"))
        assertFalse(invite(*request, "RECURRENCE-ID:garbage").offersRsvp("REQUEST"))
        val badSequence = request.map { if (it.startsWith("SEQUENCE")) "SEQUENCE:99999999999" else it }
        assertFalse(invite(*badSequence.toTypedArray()).offersRsvp("REQUEST"))
    }

    @Test
    fun uidIsCopiedVerbatimIncludingSurroundingSpaces() {
        val event = invite(*request.filterNot { it.startsWith("UID") }.toTypedArray(), "UID: event@example.com ").primary
        assertEquals(" event@example.com ", event.uid)
        val lines = unfold(rsvpDraft(event, "me@example.com", Rsvp.ACCEPTED, now).calendarReply!!).split("\r\n")
        assertTrue("UID: event@example.com " in lines)
        // Blank is no UID at all.
        assertFalse(invite(*request.filterNot { it.startsWith("UID") }.toTypedArray(), "UID:   ").offersRsvp("REQUEST"))
    }

    @Test
    fun aliasAnswerAlsoSendsFromTheAlias() {
        val event = invite(*request).primary
        assertEquals("alias@example.com", rsvpDraft(event, "alias@example.com", Rsvp.ACCEPTED, now, sendAs = "alias@example.com").from)
        assertEquals("", rsvpDraft(event, "me@example.com", Rsvp.ACCEPTED, now).from)
    }

    @Test
    fun aTwoHundredWithoutTheAckIsPlainMailNotAnRsvp() {
        fun ok(ack: Boolean) = MailOutcome.Success(MailSendOutcome(sentSaved = true, warning = "", calendarReplySent = ack))
        assertEquals(RsvpResult.SENT, rsvpResult(ok(true)))
        assertEquals(RsvpResult.SENT_AS_PLAIN_MAIL, rsvpResult(ok(false)))
        assertEquals(RsvpResult.REFUSED, rsvpResult(MailOutcome.BadRequest("invalid calendar reply: x")))
        assertEquals(RsvpResult.MAYBE_SENT, rsvpResult(MailOutcome.UpstreamFailure("timeout")))
    }

    @Test
    fun onlyADefiniteRefusalIsSafeToRetry() {
        assertTrue(MailOutcome.BadRequest("invalid calendar reply: x").refusedBeforeSending())
        assertTrue(MailOutcome.RateLimited("slow down", 10).refusedBeforeSending())
        assertFalse(MailOutcome.UpstreamFailure("timeout").refusedBeforeSending())
        assertFalse(MailOutcome.Success(Unit).refusedBeforeSending())
    }

    @Test
    fun longUidIsFoldedWithoutSplittingUtf8() {
        val uid = "é".repeat(300) + "@example.com"
        val event = invite(*request.filterNot { it.startsWith("UID") }.toTypedArray(), "UID:$uid").primary
        val ics = rsvpDraft(event, "me@example.com", Rsvp.ACCEPTED, now).calendarReply!!
        assertRelayAccepts(ics)
        assertTrue("UID:$uid" in unfold(ics))
        // Every physical line decodes on its own: no fold landed inside a two-byte sequence.
        ics.split("\r\n").forEach { assertFalse('\uFFFD' in String(it.toByteArray(), Charsets.UTF_8)) }
    }

    @Test
    fun unlistedUserFallsBackToThePrimaryAddress() {
        val event = invite(*request).primary
        assertEquals("primary@example.com", rsvpAttendee(event, listOf("primary@example.com", "other@example.com")))
    }

    @Test
    fun noUsableAccountAddressMeansNoReply() {
        val event = invite(*request).primary
        assertNull(rsvpAttendee(event, emptyList()))
        // A relay-supplied address carrying CRLF could inject an ics line; it is not an address.
        assertNull(rsvpAttendee(event, listOf("me@example.com\r\nATTENDEE:mailto:x@y")))
        assertFailsWith<IllegalArgumentException> { rsvpDraft(event, "bad address", Rsvp.ACCEPTED, now) }
    }

    @Test
    fun rsvpIsOfferedOnlyForAnAnswerableRequestFromANewEnoughRelay() {
        assertTrue(invite(*request).offersRsvp("REQUEST"))
        // An older relay lists no calendarMethod and would drop calendarReply.
        assertFalse(invite(*request).offersRsvp(""))
        assertFalse(invite(*request, method = "CANCEL").offersRsvp("CANCEL"))
        assertFalse(invite(*request, method = "PUBLISH").offersRsvp("PUBLISH"))
        val noOrganizer = invite(*request.filterNot { it.startsWith("ORGANIZER") }.toTypedArray())
        assertFalse(noOrganizer.offersRsvp("REQUEST"))
        val noUid = invite(*request.filterNot { it.startsWith("UID") }.toTypedArray())
        assertFalse(noUid.offersRsvp("REQUEST"))
    }

    @Test
    fun attendeesAreCollectedNotJustTheFirst() {
        assertEquals(listOf("me@example.com", "Alias@Example.com"), invite(*request).primary.attendees)
    }
}
