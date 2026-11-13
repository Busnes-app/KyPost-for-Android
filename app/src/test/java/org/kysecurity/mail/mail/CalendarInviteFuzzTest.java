package org.kysecurity.mail.mail;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.code_intelligence.jazzer.api.FuzzedDataProvider;
import com.code_intelligence.jazzer.junit.FuzzTest;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.util.Arrays;
import java.util.List;

/**
 * Fuzzes {@code parseCalendarInvite}, the parser for the {@code text/calendar} part of any mail:
 * every sender on the internet can put bytes in front of it, and its output drives the invite card
 * and the iTIP REPLY the user's RSVP sends.
 *
 * <p>Java on purpose: OpenSSF Scorecard detects Jazzer only in {@code .java} files.
 *
 * <p>A plain unit-test run (CI's {@code test*UnitTest}) replays the seeds in
 * {@code src/test/resources/org/kysecurity/mail/mail/CalendarInviteFuzzTestInputs/parse/} plus an
 * empty input. Fuzz it for real with {@code JAZZER_FUZZ=1}; see app/src/test/AGENTS.md.
 */
class CalendarInviteFuzzTest {

    private static final ZoneId[] ZONES = {
        ZoneId.of("UTC"), ZoneId.of("Europe/Berlin"), ZoneId.of("America/New_York"), ZoneId.of("Pacific/Chatham"),
    };

    private static final Instant NOW = Instant.parse("2026-11-13T12:00:00Z");

    @FuzzTest(maxDuration = "60s")
    void parse(FuzzedDataProvider data) {
        ZoneId zone = ZONES[data.consumeInt(0, ZONES.length - 1)];
        boolean windowsTable = data.consumeBoolean();
        byte[] ics = data.consumeRemainingAsBytes();

        // Outlook names, the shape EmailDetailActivity's ICU lookup answers; a lookup that throws
        // must not take the parser down with it.
        CalendarInvite invite = CalendarInviteKt.parseCalendarInvite(ics, zone, tzid -> {
            if (!windowsTable) return null;
            if (tzid.equals("Pacific Standard Time")) return "America/Los_Angeles";
            if (tzid.equals("Throw")) throw new IllegalStateException("lookup failed");
            return tzid.isEmpty() ? null : "Not/AZone";
        });
        if (invite == null) return;

        assertFalse(invite.getEvents().isEmpty());
        assertTrue(invite.getEvents().size() <= CalendarInviteKt.MAX_INVITE_EVENTS);
        assertTrue(invite.getMethod().isEmpty() || invite.getMethod().matches("[A-Z][A-Z0-9-]{0,31}"));
        // The headline event is the series master, never an override.
        assertNull(invite.getPrimary().getRecurrenceId());

        for (CalendarEvent event : invite.getEvents()) {
            assertFalse(event.getEnd().isBefore(event.getBegin()));
            assertTrue(event.getSummary().length() <= 1_000);
            assertTrue(event.getLocation().length() <= 1_000);
            assertTrue(event.getDescription().length() <= CalendarInviteKt.MAX_DESCRIPTION_CHARS);
            assertNoBidiOrControls(event.getSummary());
            assertNoBidiOrControls(event.getLocation());
            if (!event.getCanReply()) continue;

            // Everything the REPLY copies came from the sender. It must arrive unchanged and add no
            // line of its own: a CR or LF smuggled into UID or ORGANIZER would forge iTIP fields.
            MailDraft draft = CalendarInviteKt.rsvpDraft(event, "me@example.org", Rsvp.ACCEPTED, NOW, "");
            assertEquals(event.getOrganizer(), draft.getTo());
            String reply = draft.getCalendarReply();
            assertNotNull(reply);
            assertTrue(reply.endsWith("\r\n"));
            for (String line : reply.substring(0, reply.length() - 2).split("\r\n", -1)) {
                assertFalse(line.isEmpty());
                assertTrue(line.getBytes(StandardCharsets.UTF_8).length <= 75, line);
                for (char c : line.toCharArray()) assertFalse(c < ' ' || c == '\u007f', line);
            }
            List<String> lines = Arrays.asList(reply.replace("\r\n ", "").split("\r\n"));
            assertEquals(1, count(lines, "METHOD"));
            assertEquals(1, count(lines, "BEGIN:VEVENT"));
            assertEquals(1, count(lines, "UID"));
            assertEquals(1, count(lines, "ORGANIZER"));
            assertTrue(lines.contains("UID:" + event.getUid()));
            assertTrue(lines.contains("SEQUENCE:" + event.getSequence()));
            assertTrue(lines.contains("ORGANIZER:mailto:" + event.getOrganizer()));
            if (event.getRecurrenceId() != null) continue;

            // Our own parser reads the REPLY back. It insists on DTSTART, which a REPLY need not carry.
            // Matched as a whole line: an organizer address may itself contain "END:VEVENT"
            // (seed organizer-contains-end-vevent, the fuzzer's first find, was this harness bug).
            String withStart = reply.replace("\r\nEND:VEVENT\r\n", "\r\nDTSTART:20261012T100000Z\r\nEND:VEVENT\r\n");
            CalendarInvite echoed = CalendarInviteKt.parseCalendarInvite(
                withStart.getBytes(StandardCharsets.UTF_8), zone, tzid -> null);
            assertNotNull(echoed, reply);
            assertEquals("REPLY", echoed.getMethod());
            assertEquals(1, echoed.getEvents().size());
            assertEquals(event.getUid(), echoed.getPrimary().getUid());
            assertEquals(event.getSequence(), echoed.getPrimary().getSequence());
            assertEquals(event.getOrganizer(), echoed.getPrimary().getOrganizer());
        }
    }

    private static long count(List<String> lines, String name) {
        return lines.stream().filter(l -> l.equals(name) || l.startsWith(name + ":") || l.startsWith(name + ";")).count();
    }

    private static void assertNoBidiOrControls(String text) {
        for (char c : text.toCharArray()) {
            if (c == '\n' || c == '\t' || c == '‍') continue;
            assertFalse(Character.isISOControl(c) || Character.getType(c) == Character.FORMAT, text);
        }
    }
}
