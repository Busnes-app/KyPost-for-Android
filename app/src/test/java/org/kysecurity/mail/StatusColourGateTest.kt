package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlin.math.PI
import kotlin.math.abs
import kotlin.math.atan2
import kotlin.math.cbrt
import kotlin.math.cos
import kotlin.math.exp
import kotlin.math.hypot
import kotlin.math.pow
import kotlin.math.sin
import kotlin.math.sqrt

/**
 * Port of ky-ui's `scripts/check-status-colours.mjs` over all twelve halves: each status colour
 * reads at 4.5:1 on bg, on panel and on its own soft tint; danger sits ΔE00 ≥ 20 from the accent;
 * and accent, danger, warning and success sit ΔE00 ≥ 10 from one another.
 */
class StatusColourGateTest {

    private val halves = THEME_PAIRS.flatMap { listOf("${it.id} light" to it.light, "${it.id} dark" to it.dark) }

    private fun checks(): List<Triple<String, Double, Double>> = halves.flatMap { (name, p) ->
        val statuses = listOf("danger" to p.danger, "warning" to p.warning, "success" to p.success)
        val text = statuses.flatMap { (s, color) ->
            listOf(
                Triple("$name: $s on bg", contrast(color, p.bg), MIN_CONTRAST),
                Triple("$name: $s on panel", contrast(color, p.panel), MIN_CONTRAST),
                Triple("$name: $s on $s-soft", contrast(color, p.statusSoft(color)), MIN_CONTRAST),
            )
        }
        val named = mapOf("accent" to p.accent, "danger" to p.danger, "warning" to p.warning, "success" to p.success)
        val distance = listOf(
            "accent" to "warning", "accent" to "success", "danger" to "warning",
            "danger" to "success", "warning" to "success",
        ).map { (a, b) -> Triple("$name: ΔE $a–$b", deltaE(named.getValue(a), named.getValue(b)), MIN_OTHER) }
        text + Triple("$name: ΔE accent–danger", deltaE(p.accent, p.danger), MIN_ACCENT_DANGER) + distance
    }

    @Test
    fun everyHalfPassesTheStatusColourGate() {
        val all = checks()
        // ky-ui reports "180 checks pass across 12 halves"; the same count proves nothing was skipped.
        assertEquals(180, all.size)
        val failures = all.filter { (_, value, min) -> value < min }
            .map { (check, value, min) -> "$check %.2f < $min".format(value) }
        assertTrue(failures.joinToString("\n"), failures.isEmpty())
    }

    @Test
    fun deltaEMatchesTheSharmaReferenceData() {
        // Sharma, Wu and Dalal (2005), table 1, pairs 1 and 17.
        assertEquals(2.0425, ciede2000(doubleArrayOf(50.0, 2.6772, -79.7751), doubleArrayOf(50.0, 0.0, -82.7485)), 1e-4)
        assertEquals(27.1492, ciede2000(doubleArrayOf(50.0, 2.5, 0.0), doubleArrayOf(73.0, 25.0, -18.0)), 1e-4)
    }

    @Test
    fun contrastMatchesWcag() {
        assertEquals(21.0, contrast("#000000", "#ffffff"), 1e-9)
        assertEquals(1.0, contrast("#bf3f18", "#bf3f18"), 1e-9)
    }

    private companion object {
        const val MIN_CONTRAST = 4.5
        const val MIN_ACCENT_DANGER = 20.0
        const val MIN_OTHER = 10.0
    }
}

private fun rgb(hex: String) = (0..2).map { hex.substring(1 + 2 * it, 3 + 2 * it).toInt(16) }

private fun linear(channel: Int): Double {
    val v = channel / 255.0
    return if (v <= 0.04045) v / 12.92 else ((v + 0.055) / 1.055).pow(2.4)
}

/** WCAG relative luminance of `#rrggbb`. */
internal fun luminance(hex: String): Double {
    val (r, g, b) = rgb(hex).map(::linear)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b
}

internal fun contrast(a: String, b: String): Double {
    val hi = maxOf(luminance(a), luminance(b))
    val lo = minOf(luminance(a), luminance(b))
    return (hi + 0.05) / (lo + 0.05)
}

private fun lab(hex: String): DoubleArray {
    val (r, g, b) = rgb(hex).map(::linear)
    val xyz = listOf(
        (0.4124564 * r + 0.3575761 * g + 0.1804375 * b) / 0.95047,
        0.2126729 * r + 0.7151522 * g + 0.072175 * b,
        (0.0193339 * r + 0.119192 * g + 0.9503041 * b) / 1.08883,
    ).map { t -> if (t > 216.0 / 24389) cbrt(t) else (24389.0 / 27 * t + 16) / 116 }
    return doubleArrayOf(116 * xyz[1] - 16, 500 * (xyz[0] - xyz[1]), 200 * (xyz[1] - xyz[2]))
}

internal fun deltaE(a: String, b: String) = ciede2000(lab(a), lab(b))

/** Sharma, Wu and Dalal (2005), kL = kC = kH = 1; line for line with ky-ui's. */
internal fun ciede2000(lab1: DoubleArray, lab2: DoubleArray): Double {
    val (l1, a1, b1) = lab1.toList()
    val (l2, a2, b2) = lab2.toList()
    val rad = PI / 180
    val c = (hypot(a1, b1) + hypot(a2, b2)) / 2
    val g = 0.5 * (1 - sqrt(c.pow(7) / (c.pow(7) + 25.0.pow(7))))
    val ap1 = a1 * (1 + g)
    val ap2 = a2 * (1 + g)
    val cp1 = hypot(ap1, b1)
    val cp2 = hypot(ap2, b2)
    fun hue(b: Double, a: Double) = (atan2(b, a) / rad + 360) % 360
    val hp1 = hue(b1, ap1)
    val hp2 = hue(b2, ap2)
    val dL = l2 - l1
    val dC = cp2 - cp1
    var dh = if (cp1 * cp2 == 0.0) 0.0 else hp2 - hp1
    if (dh > 180) dh -= 360 else if (dh < -180) dh += 360
    val dH = 2 * sqrt(cp1 * cp2) * sin(dh * rad / 2)
    val lm = (l1 + l2) / 2
    val cm = (cp1 + cp2) / 2
    var hm = hp1 + hp2
    if (cp1 * cp2 != 0.0) hm = if (abs(hp1 - hp2) > 180) (hm + (if (hm < 360) 360 else -360)) / 2 else hm / 2
    val t = 1 - 0.17 * cos((hm - 30) * rad) + 0.24 * cos(2 * hm * rad) +
        0.32 * cos((3 * hm + 6) * rad) - 0.2 * cos((4 * hm - 63) * rad)
    val sl = 1 + 0.015 * (lm - 50).pow(2) / sqrt(20 + (lm - 50).pow(2))
    val sc = 1 + 0.045 * cm
    val sh = 1 + 0.015 * cm * t
    val rt = -2 * sqrt(cm.pow(7) / (cm.pow(7) + 25.0.pow(7))) * sin(60 * exp(-((hm - 275) / 25).pow(2)) * rad)
    return sqrt((dL / sl).pow(2) + (dC / sc).pow(2) + (dH / sh).pow(2) + rt * (dC / sc) * (dH / sh))
}
