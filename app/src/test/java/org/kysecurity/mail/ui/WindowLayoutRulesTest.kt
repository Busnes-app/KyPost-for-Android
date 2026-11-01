package org.kysecurity.mail.ui

import android.graphics.Rect
import androidx.window.layout.FoldingFeature
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

/**
 * The size-class → layout decision. The app makes it with resource qualifiers (`nav_is_rail` and
 * the layout aliases) and the split rule's `splitMinWidthDp`; this reads those files and resolves
 * them the way Android does for the two qualifiers in play, at real foldable window sizes.
 */
class WindowLayoutRulesTest {

    private val res = listOf(File("src/main/res"), File("app/src/main/res")).first { it.isDirectory }

    private enum class Layout { PHONE, RAIL, RAIL_TWO_PANE }

    /** Every `values*` dir that sets nav_is_rail, with its w<N>dp and notlong qualifiers. */
    private data class Rule(val minWidthDp: Int, val notLongOnly: Boolean, val rail: Boolean)

    private val rules: List<Rule> by lazy {
        res.listFiles { f -> f.isDirectory && (f.name == "values" || f.name.startsWith("values-")) }.orEmpty()
            .mapNotNull { dir ->
                val bools = File(dir, "bools.xml").takeIf(File::isFile) ?: return@mapNotNull null
                val value = Regex("""<bool name="nav_is_rail">(\w+)</bool>""").find(bools.readText())
                    ?: return@mapNotNull null
                val qualifiers = dir.name.split('-').drop(1)
                assertTrue("unexpected qualifier in ${dir.name}", qualifiers.all { it == "notlong" || it.matches(Regex("""w\d+dp""")) })
                Rule(
                    minWidthDp = qualifiers.firstNotNullOfOrNull { Regex("""w(\d+)dp""").matchEntire(it)?.groupValues?.get(1)?.toInt() } ?: 0,
                    notLongOnly = "notlong" in qualifiers,
                    rail = value.groupValues[1].toBoolean(),
                )
            }
    }

    private val splitMinWidthDp: Int by lazy {
        val values = Regex("""splitMinWidthDp="(\d+)"""").findAll(File(res, "xml/split_config.xml").readText())
            .map { it.groupValues[1].toInt() }.toSet()
        assertEquals("both split rules share one threshold", 1, values.size)
        values.single()
    }

    /** Android's own test: a screen is long when its long side is at least 5/3 of its short side. */
    private fun isLong(widthDp: Int, heightDp: Int): Boolean {
        val long = maxOf(widthDp, heightDp)
        val short = minOf(widthDp, heightDp)
        return long * 3 / 5 >= short - 1
    }

    private fun layoutFor(widthDp: Int, heightDp: Int): Layout {
        val long = isLong(widthDp, heightDp)
        // Width outranks screen aspect, so the largest matching w<N>dp decides.
        val rule = rules.filter { widthDp >= it.minWidthDp && (!it.notLongOnly || !long) }.maxByOrNull { it.minWidthDp }!!
        return when {
            !rule.rail -> Layout.PHONE
            widthDp >= splitMinWidthDp -> Layout.RAIL_TWO_PANE
            else -> Layout.RAIL
        }
    }

    @Test
    fun breakpointsAreMaterialWidthClasses() {
        assertTrue(rules.any { it.rail && it.minWidthDp == MATERIAL_MEDIUM_DP && !it.notLongOnly })
        assertEquals(MATERIAL_EXPANDED_DP, splitMinWidthDp)
        assertEquals(Rule(0, false, false), rules.single { it.minWidthDp == 0 })
    }

    @Test
    fun wideWindowsGetTheRail() {
        assertEquals(Layout.RAIL_TWO_PANE, layoutFor(841, 701)) // Pixel Fold inner, landscape
        assertEquals(Layout.RAIL, layoutFor(701, 841)) // Pixel Fold inner, portrait
        assertEquals(Layout.RAIL, layoutFor(673, 841)) // 7.6in Foldable inner
        assertEquals(Layout.RAIL, layoutFor(750, 832)) // Galaxy Z Fold-class inner, near square
        assertEquals(Layout.RAIL, layoutFor(600, 960)) // exactly medium, even when long
        assertEquals(Layout.RAIL_TWO_PANE, layoutFor(915, 411)) // tall phone turned sideways
    }

    @Test
    fun tallWindowsKeepThePhoneLayout() {
        assertEquals(Layout.PHONE, layoutFor(411, 797)) // Pixel Fold cover
        assertEquals(Layout.PHONE, layoutFor(411, 1004)) // 6.7in Foldable (flip), open
        assertEquals(Layout.PHONE, layoutFor(384, 939)) // Galaxy Z Flip-class inner
        assertEquals(Layout.PHONE, layoutFor(373, 841)) // a split-screen half of an unfolded inner
        assertEquals(Layout.PHONE, layoutFor(599, 1000)) // just under medium
    }

    @Test
    fun squarishCoversNarrowerThan440dpKeepThePhoneLayout() {
        assertEquals(Layout.PHONE, layoutFor(360, 380)) // flip cover screen
        assertEquals(Layout.PHONE, layoutFor(412, 440))
        assertEquals(Layout.RAIL, layoutFor(475, 751)) // the squarish book-fold cover the rail was added for
    }

    @Test
    fun onlyASeparatingVerticalFoldMovesTheSplit() {
        assertFalse(splitsAtHinge(null))
        assertFalse(splitsAtHinge(fold(separating = false, FoldingFeature.Orientation.VERTICAL)))
        assertTrue(splitsAtHinge(fold(separating = true, FoldingFeature.Orientation.VERTICAL)))
        assertFalse(splitsAtHinge(fold(separating = true, FoldingFeature.Orientation.HORIZONTAL)))
    }

    private fun fold(separating: Boolean, orientation: FoldingFeature.Orientation) = object : FoldingFeature {
        override val isSeparating = separating
        override val orientation = orientation
        override val occlusionType = FoldingFeature.OcclusionType.NONE
        override val state = if (separating) FoldingFeature.State.HALF_OPENED else FoldingFeature.State.FLAT
        override val bounds: Rect get() = throw UnsupportedOperationException()
    }

    private companion object {
        // androidx.window's WindowSizeClass.WIDTH_DP_MEDIUM_LOWER_BOUND and _EXPANDED_LOWER_BOUND.
        // window-core reaches the app only at runtime, so its constants aren't on this classpath.
        const val MATERIAL_MEDIUM_DP = 600
        const val MATERIAL_EXPANDED_DP = 840
    }
}
