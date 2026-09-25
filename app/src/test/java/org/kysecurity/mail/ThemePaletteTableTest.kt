package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The palette table is data, and a typo in it silently falls back to [DEFAULT_THEME] or throws
 * inside `Color.parseColor` on a device. `android.graphics.Color` is unmocked here (see
 * `unitTests.isReturnDefaultValues = false`), so the hex is checked by shape instead.
 */
class ThemePaletteTableTest {

    private val hex = Regex("^#[0-9a-fA-F]{6}$")

    @Test
    fun everyOfferedThemeHasItsOwnPalette() {
        assertEquals(THEME_OPTIONS.toSet(), themePalettes.keys)
        assertEquals(THEME_OPTIONS.size, THEME_OPTIONS.toSet().size)
    }

    @Test
    fun theDefaultIsBusnesLightAndIsOffered() {
        assertEquals("Busnes Light", DEFAULT_THEME)
        assertTrue(THEME_OPTIONS.contains(DEFAULT_THEME))
        assertTrue(themePalettes.containsKey(DEFAULT_THEME))
    }

    @Test
    fun everyPaletteFieldIsOpaqueSixDigitHex() {
        themePalettes.forEach { (name, palette) ->
            val fields = listOf(
                palette.bg, palette.panel, palette.ink, palette.inkStrong, palette.accent,
                palette.line, palette.avatarGradientStart, palette.avatarGradientEnd,
                palette.avatarBorder,
            )
            fields.forEach { value ->
                assertTrue("$name has non-opaque or malformed color $value", hex.matches(value))
            }
        }
    }

    @Test
    fun theBusnesPalettesMatchTheHandoff() {
        val light = themePaletteFor("Busnes Light")
        assertEquals("#f8f6f0", light.bg)
        assertEquals("#ffffff", light.panel)
        assertEquals("#566461", light.ink)
        assertEquals("#182326", light.inkStrong)
        assertEquals("#bf3f18", light.accent)

        val dark = themePaletteFor("Busnes Dark")
        assertEquals("#182326", dark.bg)
        assertEquals("#1f2b2e", dark.panel)
        assertEquals("#b3bcb8", dark.ink)
        assertEquals("#f2efe8", dark.inkStrong)
        assertEquals("#f5865f", dark.accent)
    }
}
