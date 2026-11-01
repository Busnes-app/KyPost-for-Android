package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

/** Saved theme values from before the six pairs, and the new two-key form. */
class ThemeMigrationTest {

    private fun pair(id: String) = THEME_PAIRS.single { it.id == id }
    private fun choice(id: String, mode: ThemeMode) = ThemeChoice(pair(id), mode)

    @Test
    fun nothingSavedIsBusnesFollowingTheSystem() {
        assertEquals(DEFAULT_THEME_CHOICE, resolveThemeChoice(null, null))
    }

    @Test
    fun theOldFollowSystemIsBusnesFollowingTheSystem() {
        assertEquals(DEFAULT_THEME_CHOICE, resolveThemeChoice("Follow system", null))
    }

    @Test
    fun anOldBusnesHalfKeepsItsHalfForced() {
        assertEquals(choice("busnes-pair", ThemeMode.LIGHT), resolveThemeChoice("Busnes Light", null))
        assertEquals(choice("busnes-pair", ThemeMode.DARK), resolveThemeChoice("Busnes Dark", null))
    }

    @Test
    fun anOldSurvivingHalfKeepsItsPairAndHalf() {
        assertEquals(choice("matter-pair", ThemeMode.LIGHT), resolveThemeChoice("Light Matter", null))
        assertEquals(choice("matter-pair", ThemeMode.DARK), resolveThemeChoice("Dark Matter", null))
        assertEquals(choice("ocean-pair", ThemeMode.LIGHT), resolveThemeChoice("White Cliffs", null))
        assertEquals(choice("ocean-pair", ThemeMode.DARK), resolveThemeChoice("Ocean", null))
        assertEquals(choice("forest-pair", ThemeMode.DARK), resolveThemeChoice("Forest", null))
        assertEquals(choice("ky-pair", ThemeMode.LIGHT), resolveThemeChoice("Polished Ky", null))
        assertEquals(choice("ky-pair", ThemeMode.DARK), resolveThemeChoice("Patina Ky", null))
    }

    @Test
    fun everyRemovedPaletteResetsToBusnesFollowingTheSystem() {
        listOf("Tropics", "Tropic Night", "Coffee", "Cyber Punk", "Neon Purple", "Space", "Sky", "Sun", "Retired Theme", "")
            .forEach { assertEquals(it, DEFAULT_THEME_CHOICE, resolveThemeChoice(it, null)) }
    }

    @Test
    fun aLegacyNameIgnoresAStrayModeKey() {
        assertEquals(choice("busnes-pair", ThemeMode.DARK), resolveThemeChoice("Busnes Dark", "light"))
        assertEquals(DEFAULT_THEME_CHOICE, resolveThemeChoice("Coffee", "dark"))
    }

    @Test
    fun aSavedPairReadsItsMode() {
        assertEquals(choice("nord-pair", ThemeMode.DARK), resolveThemeChoice("nord-pair", "dark"))
        assertEquals(choice("nord-pair", ThemeMode.LIGHT), resolveThemeChoice("nord-pair", "light"))
        assertEquals(choice("nord-pair", ThemeMode.SYSTEM), resolveThemeChoice("nord-pair", "system"))
    }

    @Test
    fun aSavedPairWithAMissingOrUnknownModeFollowsTheSystem() {
        assertEquals(choice("ky-pair", ThemeMode.SYSTEM), resolveThemeChoice("ky-pair", null))
        assertEquals(choice("ky-pair", ThemeMode.SYSTEM), resolveThemeChoice("ky-pair", "sepia"))
    }

    @Test
    fun everyChoiceRoundTripsThroughItsStoredValues() {
        THEME_PAIRS.forEach { pair ->
            ThemeMode.values().forEach { mode ->
                val chosen = ThemeChoice(pair, mode)
                assertEquals(chosen, resolveThemeChoice(chosen.pair.id, chosen.mode.storageValue))
            }
        }
    }
}
