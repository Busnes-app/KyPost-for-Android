package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.ZoneId
import java.time.ZonedDateTime
import java.util.Locale

class InboxRowStateTest {

    private val now = ZonedDateTime.of(2026, 10, 10, 15, 0, 0, 0, ZoneId.of("America/New_York"))

    @Test
    fun todayShowsLocalTime() {
        val shown = inboxRowDate("2026-10-10T13:05:00Z", now, Locale.US)
        assertTrue(shown, shown.startsWith("9:05"))
    }

    @Test
    fun earlierDayShowsDate() {
        assertEquals("Oct 9, 2026", inboxRowDate("2026-10-09T13:05:00Z", now, Locale.US))
    }

    @Test
    fun dayIsTheLocalDayNotTheUtcDay() {
        // 02:00 UTC on the 10th is still the 9th in New York.
        assertEquals("Oct 9, 2026", inboxRowDate("2026-10-10T02:00:00Z", now, Locale.US))
    }

    @Test
    fun missingOrMalformedDateIsBlank() {
        assertEquals("", inboxRowDate(null, now, Locale.US))
        assertEquals("", inboxRowDate("", now, Locale.US))
        assertEquals("", inboxRowDate("yesterday", now, Locale.US))
    }

    @Test
    fun emptyStateWaitsForTheFolderToLoad() {
        assertFalse(inboxEmptyVisible(0, loadedFolder = null, currentFolder = "INBOX"))
        assertFalse(inboxEmptyVisible(0, loadedFolder = "Junk", currentFolder = "INBOX"))
        assertFalse(inboxEmptyVisible(3, loadedFolder = "INBOX", currentFolder = "INBOX"))
        assertTrue(inboxEmptyVisible(0, loadedFolder = "INBOX", currentFolder = "INBOX"))
    }
}
