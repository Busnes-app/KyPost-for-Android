package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Duration
import java.time.ZoneId
import java.time.ZonedDateTime

class WhenPickerTest {

    private val zone = ZoneId.of("America/New_York")
    private val year = Duration.ofDays(365)
    private val minute = Duration.ofMinutes(1)

    private fun at(day: Int, hour: Int, minute: Int = 0) = ZonedDateTime.of(2026, 10, day, hour, minute, 0, 0, zone)

    @Test
    fun aMorningOffersEveryPreset() {
        // Tuesday 13 October, 09:20.
        val presets = whenPresets(at(13, 9, 20), minute, year)
        assertEquals(
            listOf(
                R.string.when_later_today to at(13, 12),
                R.string.when_this_evening to at(13, 18),
                R.string.when_tomorrow to at(14, 8),
                R.string.when_next_week to at(19, 8),
            ),
            presets.map { it.label to it.at },
        )
    }

    @Test
    fun lateInTheDayDropsWhatHasPassed() {
        // 21:30: the evening has passed, and three hours on is tomorrow. At 17:30 it is within the hour.
        assertEquals(
            listOf(R.string.when_tomorrow, R.string.when_next_week),
            whenPresets(at(13, 21, 30), minute, year).map { it.label },
        )
        assertFalse(whenPresets(at(13, 17, 30), minute, year).any { it.label == R.string.when_this_evening })
    }

    @Test
    fun laterTodayLandingOnSixIsOfferedOnce() {
        val presets = whenPresets(at(13, 15, 10), minute, year)
        assertEquals(1, presets.count { it.at == at(13, 18) })
    }

    @Test
    fun aShortWindowKeepsOnlyWhatFits() {
        assertEquals(
            listOf(R.string.when_later_today, R.string.when_this_evening),
            whenPresets(at(13, 9, 20), minute, Duration.ofHours(12)).map { it.label },
        )
    }

    @Test
    fun theWindowIncludesItsEnds() {
        val now = at(13, 9)
        assertTrue(inWindow(now.plus(minute), now, minute, year))
        assertTrue(inWindow(now.plus(year), now, minute, year))
        assertFalse(inWindow(now, now, minute, year))
        assertFalse(inWindow(now.plus(year).plusSeconds(1), now, minute, year))
    }
}
