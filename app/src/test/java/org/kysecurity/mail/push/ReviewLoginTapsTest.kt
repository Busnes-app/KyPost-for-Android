package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReviewLoginTapsTest {

    @Test
    fun nineTapsDoNothingAndTheTenthOpens() {
        val taps = ReviewLoginTaps()

        val results = List(10) { taps.tap() }

        assertEquals(List(9) { false } + true, results)
    }

    @Test
    fun theSequenceStartsOverAfterOpening() {
        val taps = ReviewLoginTaps()
        repeat(10) { taps.tap() }

        val results = List(10) { taps.tap() }

        assertEquals(List(9) { false } + true, results)
    }

    @Test
    fun armedOnlyOnPlayBeforeTheFirstPairing() {
        assertTrue(ReviewLoginTaps.armed(flavor = "play", everPaired = false))
        assertFalse(ReviewLoginTaps.armed(flavor = "play", everPaired = true))
        assertFalse(ReviewLoginTaps.armed(flavor = "fdroid", everPaired = false))
        assertFalse(ReviewLoginTaps.armed(flavor = "github", everPaired = false))
    }
}
