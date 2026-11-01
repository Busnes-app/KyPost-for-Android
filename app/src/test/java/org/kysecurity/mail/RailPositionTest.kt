package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RailPositionTest {

    @Test
    fun nothingSavedMeansRight() {
        assertEquals(RailPosition.RIGHT, resolveRailPosition(null))
    }

    @Test
    fun savedLeftIsHonoured() {
        assertEquals(RailPosition.LEFT, resolveRailPosition("left"))
        assertEquals(RailPosition.RIGHT, resolveRailPosition("right"))
    }

    @Test
    fun anUnknownValueFallsBackToRight() {
        assertEquals(RailPosition.RIGHT, resolveRailPosition("middle"))
        assertEquals(RailPosition.RIGHT, resolveRailPosition(""))
    }

    @Test
    fun valuesRoundTripThroughStorage() {
        RailPosition.values().forEach { assertEquals(it, resolveRailPosition(it.storageValue)) }
    }

    @Test
    fun theKeyIsItsOwn() {
        assertFalse(RAIL_POSITION_STORAGE_KEY == THEME_STORAGE_KEY)
        assertFalse(RAIL_POSITION_STORAGE_KEY == THEME_MODE_STORAGE_KEY)
    }

    /** Right and Left are physical: right-to-left swaps the layout edge, not the side seen. */
    @Test
    fun sidesArePhysical() {
        assertTrue(railAtEnd(RailPosition.RIGHT, rtl = false))
        assertFalse(railAtEnd(RailPosition.LEFT, rtl = false))
        assertFalse(railAtEnd(RailPosition.RIGHT, rtl = true))
        assertTrue(railAtEnd(RailPosition.LEFT, rtl = true))
    }
}
