package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class InlineImagesTest {

    private val png = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47)
    private fun logo(id: String = "logo@kypost", type: String = "image/png", bytes: ByteArray = png) =
        DecryptedAttachment("logo.png", type, bytes, id)

    @Test
    fun rewritesAMatchingCidToADataUri() {
        val out = inlineCidImages("""<p>hi</p><img src="cid:logo@kypost">""", listOf(logo()))

        assertTrue(out, out.contains("src=\"data:image/png;base64,iVBORw==\""))
        assertTrue(out, !out.contains("cid:"))
    }

    @Test
    fun matchesCaseInsensitivelyOnTheSchemeOnly() {
        val out = inlineCidImages("""<img src="CID:logo@kypost">""", listOf(logo()))
        assertTrue(out, out.contains("data:image/png;base64,"))

        val miss = inlineCidImages("""<img src="cid:LOGO@kypost">""", listOf(logo()))
        assertTrue("Content-ID is case-sensitive", miss.contains("cid:LOGO@kypost"))
    }

    @Test
    fun leavesAnUnresolvedCidForTheSanitiserToStrip() {
        val out = inlineCidImages("""<img src="cid:missing">""", listOf(logo()))
        assertTrue(out, out.contains("cid:missing"))
    }

    @Test
    fun refusesTypesThatAreNotRasterImages() {
        // SVG can carry script and event handlers; it is never inlined even with JS off.
        val out = inlineCidImages("""<img src="cid:logo@kypost">""", listOf(logo(type = "image/svg+xml")))
        assertTrue(out, out.contains("cid:logo@kypost"))
    }

    @Test
    fun stopsInliningAtTheByteBudget() {
        val half = ByteArray((org.kysecurity.mail.MemoryBudget.INLINE_IMAGE_BYTES / 2 + 1).toInt())
        val out = inlineCidImages(
            """<img src="cid:a"><img src="cid:b">""",
            listOf(logo("a", bytes = half), logo("b", bytes = half)),
        )

        assertEquals(1, Regex("data:image/png").findAll(out).count())
        assertTrue("the second image stays a cid: and gets stripped downstream", out.contains("cid:b"))
    }

    @Test
    fun anUnparseableFragmentComesBackUntouched() {
        assertEquals("", inlineCidImages("", listOf(logo())))
    }
}
