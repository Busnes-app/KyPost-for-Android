package org.kysecurity.mail.mail

import org.junit.Test
import java.time.ZoneId
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** KyPost-Server docs/NATIVE-RSVP.md: KyCalendar first, mail only as the confirmed fallback, and
 *  the card states of KyPost-Server #606. */
class KyCalendarRsvpTest {

    private val base = listOf(
        "UID:abc-123@example.com",
        "SEQUENCE:2",
        "DTSTAMP:20261101T090000Z",
        "DTSTART:20261112T100000Z",
        "DTEND:20261112T110000Z",
        "SUMMARY:Weekly sync",
        "LOCATION:Room 1",
        "ORGANIZER:mailto:boss@example.com",
        "ATTENDEE:mailto:me@example.com",
    )

    private fun invite(vararg extra: String, method: String = "REQUEST", lines: List<String> = base) = assertNotNull(
        parseCalendarInvite(
            (listOf("BEGIN:VCALENDAR", "METHOD:$method", "BEGIN:VEVENT") + lines + extra + listOf("END:VEVENT", "END:VCALENDAR"))
                .joinToString("\r\n").toByteArray(),
            ZoneId.of("UTC"),
        ),
    )

    private fun with(name: String, value: String) = base.map { if (it.startsWith("$name:")) "$name:$value" else it }

    private val part = AttachmentInfo(index = 2, name = "invite.ics", mimeType = "text/calendar; method=REQUEST", size = 900, calendarMethod = "REQUEST")

    // The "Respond" table, row by row.

    @Test
    fun answeredIsDoneAndAnyOther200IsNotConfirmed() {
        assertEquals(CalendarAnswer.Answered, calendarAnswer(200, """{"outcome":"answered"}"""))
        listOf("""{"outcome":"duplicate"}""", "{}", "", "not json", """{"outcome":true}""").forEach {
            assertEquals(CalendarAnswer.Failed(KYCALENDAR_NOT_CONFIRMED), calendarAnswer(200, it), it)
        }
    }

    @Test
    fun onlyKyCalendarOffAndNoEventFallBackToMail() {
        assertEquals(CalendarAnswer.ByMail(noEvent = false), calendarAnswer(409, """{"error":"off","code":"kycalendar_off"}"""))
        assertEquals(CalendarAnswer.ByMail(noEvent = true), calendarAnswer(404, """{"error":"none","code":"no_event"}"""))
        assertEquals(CalendarAnswer.Conflict, calendarAnswer(409, """{"error":"changed","code":"conflict"}"""))
    }

    @Test
    fun everyOtherRefusalIsShownAndNeverMailed() {
        val rows = listOf(
            400 to "bad_request", 400 to "bad_partstat", 404 to "not_found", 422 to "not_invitation",
            422 to "not_invited", 502 to "kycalendar_unavailable", 507 to "quota", 401 to "bad_signature",
        )
        rows.forEach { (code, refusal) ->
            val answer = calendarAnswer(code, """{"error":"Server says $refusal","code":"$refusal"}""")
            assertEquals(CalendarAnswer.Failed("Server says $refusal"), answer, refusal)
        }
        // No error text: the fixed sentence. A JSON 404 is a refusal, not a missing route.
        assertEquals(CalendarAnswer.Failed(KYCALENDAR_UNREACHABLE), calendarAnswer(502, """{"code":"kycalendar_unavailable"}"""))
        assertEquals(CalendarAnswer.Failed(KYCALENDAR_UNREACHABLE), calendarAnswer(404, """{"code":"not_found"}"""))
        assertEquals(CalendarAnswer.Failed(KYCALENDAR_UNREACHABLE), calendarAnswer(500, "oops"))
        // The code in the wrong field, or not a string, is not a fallback.
        assertTrue(calendarAnswer(409, """{"error":"kycalendar_off"}""") is CalendarAnswer.Failed)
        assertTrue(calendarAnswer(409, """{"code":["kycalendar_off"]}""") is CalendarAnswer.Failed)
    }

    @Test
    fun aRelayWithoutTheRouteIsTreatedAsKyCalendarOff() {
        // Deviation, documented in app/src/main/AGENTS.md: a pre-route relay's plain-text 404.
        assertEquals(CalendarAnswer.ByMail(noEvent = false), calendarAnswer(404, "404 page not found\n"))
    }

    @Test
    fun serverErrorTextIsBoundedAndCannotReorderTheToast() {
        val answer = calendarAnswer(400, """{"error":"bad‮\u0007${"x".repeat(500)}","code":"bad_request"}""") as CalendarAnswer.Failed
        assertEquals(200, answer.message.length)
        assertFalse(answer.message.any { it == '‮' || it == '\u0007' })
    }

    // The fallback rule, through the tracker the screens share.

    @Test
    fun aFallbackWaitsForConfirmationAndIsClaimedOnce() {
        val tracker = RsvpTracker()
        val key = rsvpKey(invite().primary)
        val session = org.kysecurity.mail.ProcessState.generation()
        assertTrue(tracker.begin(key))
        assertTrue(tracker.answered(key, CalendarAnswer.ByMail(noEvent = true), Rsvp.DECLINED, session))
        val state = assertNotNull(tracker.phases.value[key])
        assertEquals(RsvpPhase.CONFIRM_MAIL, state.phase)
        assertEquals(MailFallback(Rsvp.DECLINED, noEvent = true), state.fallback)
        assertFalse(tracker.canAnswer(key))
        assertTrue(tracker.confirmMail(key))
        assertFalse(tracker.confirmMail(key), "a second screen cannot mail it again")
        tracker.finish(key, RsvpResult.SENT)
        assertFalse(tracker.canAnswer(key))
    }

    @Test
    fun cancellingTheFallbackSendsNothingAndReArms() {
        val tracker = RsvpTracker()
        val key = rsvpKey(invite().primary)
        val session = org.kysecurity.mail.ProcessState.generation()
        tracker.begin(key)
        tracker.answered(key, CalendarAnswer.ByMail(noEvent = false), Rsvp.ACCEPTED, session)
        tracker.cancel(key)
        assertTrue(tracker.canAnswer(key))
        assertFalse(tracker.confirmMail(key))
    }

    @Test
    fun answeredLocksAndEveryRefusalReArmsWithoutMail() {
        val session = org.kysecurity.mail.ProcessState.generation()
        val key = rsvpKey(invite().primary)
        RsvpTracker().apply {
            begin(key)
            answered(key, CalendarAnswer.Answered, Rsvp.ACCEPTED, session)
            assertFalse(canAnswer(key))
            assertFalse(confirmMail(key))
        }
        listOf(CalendarAnswer.Conflict, CalendarAnswer.Failed("no")).forEach { refusal ->
            RsvpTracker().apply {
                begin(key)
                answered(key, refusal, Rsvp.ACCEPTED, session)
                assertTrue(canAnswer(key), "$refusal")
                assertFalse(confirmMail(key), "$refusal")
            }
        }
    }

    @Test
    fun anAnswerFromAnEndedSessionIsDropped() {
        val tracker = RsvpTracker()
        val key = rsvpKey(invite().primary)
        val session = org.kysecurity.mail.ProcessState.generation()
        tracker.begin(key)
        org.kysecurity.mail.ProcessState.advanceGeneration()
        tracker.clear()
        assertFalse(tracker.answered(key, CalendarAnswer.ByMail(noEvent = false), Rsvp.ACCEPTED, session))
        assertTrue(tracker.phases.value.isEmpty())
    }

    // When answers are offered.

    @Test
    fun answersNeedAListedTextCalendarRequest() {
        assertTrue(invite().offersRsvp(part))
        assertFalse(invite().offersRsvp(part.copy(calendarMethod = "")))
        assertFalse(invite().offersRsvp(part.copy(calendarMethod = "PUBLISH")))
        assertFalse(invite().offersRsvp(part.copy(mimeType = "application/ics")))
    }

    // The three card states.

    @Test
    fun anUpdateToAnAnsweredInviteSaysWhatChanged() {
        val answered = invite().primary
        val record = answerRecord(answered, Rsvp.ACCEPTED, now = 1)
        assertEquals(PriorAnswer.Same(Rsvp.ACCEPTED), priorAnswer(answered, record))

        val moved = invite(lines = with("SEQUENCE", "3").map { if (it.startsWith("DTSTART")) "DTSTART:20261112T120000Z" else it }).primary
        assertEquals(PriorAnswer.Newer(Rsvp.ACCEPTED, listOf(InviteChange.TIME)), priorAnswer(moved, record))

        val renamed = invite(lines = with("SEQUENCE", "3").map {
            when {
                it.startsWith("SUMMARY") -> "SUMMARY:Monthly sync"
                it.startsWith("LOCATION") -> "LOCATION:Room 2"
                else -> it
            }
        }).primary
        assertEquals(PriorAnswer.Newer(Rsvp.ACCEPTED, listOf(InviteChange.PLACE, InviteChange.TITLE)), priorAnswer(renamed, record))

        // Same SEQUENCE, later DTSTAMP: newer, and a new revision to answer.
        val restamped = invite(lines = with("DTSTAMP", "20261102T090000Z")).primary
        assertEquals(PriorAnswer.Newer(Rsvp.ACCEPTED, emptyList()), priorAnswer(restamped, record))
        assertFalse(rsvpKey(answered) == rsvpKey(restamped))
        // An older copy reopened is the answered revision.
        assertEquals(PriorAnswer.Same(Rsvp.ACCEPTED), priorAnswer(invite(lines = with("SEQUENCE", "1")).primary, record))
    }

    @Test
    fun theStoredRecordHoldsNoReadableInviteText() {
        val event = invite().primary
        val record = answerRecord(event, Rsvp.TENTATIVE, now = 5)
        listOf("Weekly", "Room", "boss", "abc-123", "me@").forEach { assertFalse(it in record, it) }
        assertFalse("abc-123" in answerKey(event, "me@example.com"))
        listOf(null, "", "garbage", "1|2|3", "x|0|a|b|c|ACCEPTED|1", "2|0|a|b|c|MAYBE|1").forEach {
            assertEquals(PriorAnswer.None, priorAnswer(event, it), "$it")
        }
    }

    @Test
    fun aCancelIsCancelledWithNoAnswers() {
        val cancel = invite(method = "CANCEL")
        assertTrue(cancel.isCancelled)
        assertFalse(cancel.offersRsvp(part.copy(calendarMethod = "CANCEL")))
        assertFalse(cancel.offersRsvp(part))
        assertFalse(cancel.offersAdd)
    }

    @Test
    fun onlyAnHttpsConferenceGetsAJoinButton() {
        assertEquals(
            "https://chat.example/#/room/!abc:example",
            invite("CONFERENCE;VALUE=URI;FEATURE=VIDEO;LABEL=KyMessages:https://chat.example/#/room/!abc:example").primary.conference,
        )
        assertEquals("chat.example", linkTargetOf(invite("CONFERENCE;VALUE=URI:https://Chat.Example/x").primary.conference)?.host)
        listOf(
            "http://chat.example/x", "tel:+15551234", "javascript:alert(1)", "sip:me@example.com",
            "https://user:pw@chat.example/x", "https://", "data:text/html,hi",
        ).forEach { assertEquals("", invite("CONFERENCE;VALUE=URI:$it").primary.conference, it) }
        assertEquals("", invite().primary.conference)
        // The first CONFERENCE counts, like the web card.
        assertEquals("", invite("CONFERENCE;VALUE=URI:tel:+1", "CONFERENCE;VALUE=URI:https://chat.example/").primary.conference)
    }

    @Test
    fun dtstampIsReadOnlyAsUtc() {
        assertEquals(java.time.Instant.parse("2026-11-01T09:00:00Z").toEpochMilli(), invite().primary.stamp)
        assertEquals(0, invite(lines = with("DTSTAMP", "20261101T090000")).primary.stamp)
        assertEquals(0, invite(lines = with("DTSTAMP", "20261301T090000Z")).primary.stamp)
    }
}
