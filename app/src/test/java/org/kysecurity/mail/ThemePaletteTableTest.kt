package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The palette table is data, and a typo in it silently paints the wrong half or throws inside
 * `Color.parseColor` on a device. `android.graphics.Color` is unmocked here (see
 * `unitTests.isReturnDefaultValues = false`), so the hex is checked by shape instead.
 */
class ThemePaletteTableTest {

    private val hex = Regex("^#[0-9a-f]{6}$")

    private fun pair(id: String) = THEME_PAIRS.single { it.id == id }

    @Test
    fun theSixPairsInKyUiOrder() {
        assertEquals(listOf("Busnes", "Matter", "Ocean", "Forest", "Ky", "Nord"), THEME_PAIRS.map { it.name })
        assertEquals(
            listOf("busnes-pair", "matter-pair", "ocean-pair", "forest-pair", "ky-pair", "nord-pair"),
            THEME_PAIRS.map { it.id },
        )
    }

    @Test
    fun theDefaultIsBusnesFollowingTheSystem() {
        assertEquals(ThemeChoice(pair("busnes-pair"), ThemeMode.SYSTEM), DEFAULT_THEME_CHOICE)
    }

    @Test
    fun systemModePaintsTheHalfForTheSystem() {
        val busnes = pair("busnes-pair")
        assertEquals(busnes.light, themePaletteFor(DEFAULT_THEME_CHOICE, systemDark = false))
        assertEquals(busnes.dark, themePaletteFor(DEFAULT_THEME_CHOICE, systemDark = true))
    }

    @Test
    fun aForcedModeIgnoresTheSystem() {
        val forest = pair("forest-pair")
        listOf(false, true).forEach { systemDark ->
            assertEquals(forest.light, themePaletteFor(ThemeChoice(forest, ThemeMode.LIGHT), systemDark))
            assertEquals(forest.dark, themePaletteFor(ThemeChoice(forest, ThemeMode.DARK), systemDark))
        }
    }

    @Test
    fun everyLightHalfIsLightAndEveryDarkHalfIsDark() {
        THEME_PAIRS.forEach {
            assertTrue("${it.name} light half reads dark", luminance(it.light.bg) > 0.5)
            assertTrue("${it.name} dark half reads light", luminance(it.dark.bg) < 0.1)
        }
    }

    @Test
    fun everyPaletteFieldIsOpaqueSixDigitHex() {
        THEME_PAIRS.flatMap { listOf(it.name + " light" to it.light, it.name + " dark" to it.dark) }.forEach { (name, palette) ->
            val fields = listOf(
                palette.bg, palette.panel, palette.ink, palette.inkStrong, palette.accent,
                palette.line, palette.avatarGradientStart, palette.avatarGradientEnd,
                palette.avatarBorder, palette.danger, palette.warning, palette.success,
            )
            fields.forEach { value ->
                assertTrue("$name has non-opaque or malformed color $value", hex.matches(value))
            }
        }
    }

    /** ky-ui 0.11.0 `src/themes.js` and `src/tokens.css`: bg, panel, accent, danger, warning, success. */
    @Test
    fun theHalvesMatchKyUi() {
        val kyUi = mapOf(
            "busnes-pair" to (listOf("#f8f6f0", "#ffffff", "#bf3f18", "#a8174e", "#7a5f00", "#267442") to
                listOf("#182326", "#1f2b2e", "#f5865f", "#ff8fb1", "#ffd25e", "#86efac")),
            "matter-pair" to (listOf("#f5efe5", "#fff8ee", "#805a39", "#a8174e", "#7a5f00", "#267442") to
                listOf("#1d1b19", "#292725", "#c29a72", "#ff8fb1", "#ffd25e", "#86efac")),
            "ocean-pair" to (listOf("#f7f9fb", "#ffffff", "#1d5fa6", "#a8174e", "#7a5f00", "#267442") to
                listOf("#0f1b24", "#152a36", "#6aa8e8", "#ff8fb1", "#ffd25e", "#86efac")),
            "forest-pair" to (listOf("#f3f6ef", "#fcfdf9", "#4b6b37", "#a8174e", "#7a5f00", "#00737a") to
                listOf("#142018", "#1f2f24", "#8faa74", "#ff8fb1", "#ffd25e", "#6ee0d0")),
            "ky-pair" to (listOf("#eef2f6", "#ffffff", "#08758b", "#a8174e", "#7a5f00", "#267442") to
                listOf("#10161e", "#1b2530", "#6fc9cc", "#ff8fb1", "#ffd25e", "#86efac")),
            "nord-pair" to (listOf("#eceff4", "#ffffff", "#4a6a94", "#a8174e", "#7a5f00", "#267442") to
                listOf("#2e3440", "#3b4252", "#88c0d0", "#ecc4c8", "#ffd25e", "#bcd4aa")),
        )
        fun ThemePalette.key() = listOf(bg, panel, accent, danger, warning, success)
        kyUi.forEach { (id, halves) ->
            assertEquals("$id light", halves.first, pair(id).light.key())
            assertEquals("$id dark", halves.second, pair(id).dark.key())
        }
    }

    @Test
    fun statusSoftIsCssColorMixOverPanel() {
        // color-mix(in srgb, #a8174e 12%, #ffffff), as ky-ui's check-status-colours.mjs computes it.
        assertEquals("#f5e3ea", mixHex("#a8174e", 12, "#ffffff"))
        assertEquals(mixHex("#ff8fb1", 12, "#1f2b2e"), pair("busnes-pair").dark.statusSoft("#ff8fb1"))
    }
}
