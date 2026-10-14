package org.kysecurity.mail.security

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class LockoutPolicyTest {
    @Test
    fun delayMillisFor_isZero_forFirstTwoAttempts() {
        assertEquals(0L, LockoutPolicy.delayMillisFor(1))
        assertEquals(0L, LockoutPolicy.delayMillisFor(2))
    }

    @Test
    fun delayMillisFor_escalates_fromThirdAttempt() {
        assertEquals(30_000L, LockoutPolicy.delayMillisFor(3))
        assertEquals(60_000L, LockoutPolicy.delayMillisFor(4))
        assertEquals(300_000L, LockoutPolicy.delayMillisFor(5))
        assertEquals(900_000L, LockoutPolicy.delayMillisFor(6))
        assertEquals(1_800_000L, LockoutPolicy.delayMillisFor(7))
        assertEquals(3_600_000L, LockoutPolicy.delayMillisFor(8))
    }

    @Test
    fun delayMillisFor_caps_atOneHour() {
        assertEquals(3_600_000L, LockoutPolicy.delayMillisFor(9))
        assertEquals(3_600_000L, LockoutPolicy.delayMillisFor(50))
    }

    @Test
    fun shouldWipe_isFalse_belowThreshold() {
        assertFalse(LockoutPolicy.shouldWipe(9, wipeAfterAttempts = 10))
        assertFalse(LockoutPolicy.shouldWipe(29, wipeAfterAttempts = 30))
    }

    @Test
    fun shouldWipe_isTrue_atThreshold() {
        assertTrue(LockoutPolicy.shouldWipe(10, wipeAfterAttempts = 10))
        assertTrue(LockoutPolicy.shouldWipe(11, wipeAfterAttempts = 10))
    }

    @Test
    fun shouldWipe_isNeverTrue_whenTheUserTurnedItOff() {
        assertFalse(LockoutPolicy.shouldWipe(10, wipeAfterAttempts = null))
        assertFalse(LockoutPolicy.shouldWipe(1_000, wipeAfterAttempts = null))
    }

    @Test
    fun reachingTheDefaultThresholdTakesMostOfADay() {
        val hours = LockoutPolicy.timeToWipeMillis(LockoutPolicy.DEFAULT_WIPE_THRESHOLD) / 3_600_000.0
        assertTrue("expected > 12h, was ${hours}h", hours > 12.0)
    }

    @Test
    fun everyOfferedThresholdIsAtLeastSeveralHours() {
        LockoutPolicy.WIPE_THRESHOLD_CHOICES.forEach { threshold ->
            val hours = LockoutPolicy.timeToWipeMillis(threshold) / 3_600_000.0
            assertTrue("threshold $threshold reached in ${hours}h", hours > 3.0)
        }
    }

    @Test
    fun moreAttemptsOrNoWipeAtAllIsWeaker() {
        assertTrue(LockoutPolicy.weakensWipe(from = 10, to = 20))
        assertTrue(LockoutPolicy.weakensWipe(from = 30, to = null))
        assertFalse(LockoutPolicy.weakensWipe(from = 30, to = 10))
        assertFalse(LockoutPolicy.weakensWipe(from = null, to = 30))
        assertFalse(LockoutPolicy.weakensWipe(from = 20, to = 20))
        assertFalse(LockoutPolicy.weakensWipe(from = null, to = null))
    }

    @Test
    fun aLongerGraceWindowIsWeaker() {
        assertTrue(AppLockSettings.weakensGrace(from = 0L, to = 30_000L))
        assertFalse(AppLockSettings.weakensGrace(from = 300_000L, to = 0L))
        assertFalse(AppLockSettings.weakensGrace(from = 30_000L, to = 30_000L))
    }
}
