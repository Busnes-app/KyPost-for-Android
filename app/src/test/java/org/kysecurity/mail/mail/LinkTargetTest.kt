package org.kysecurity.mail.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The host shown in the confirm dialog must be the host the browser will load. */
class LinkTargetTest {

    private fun host(raw: String) = linkTargetOf(raw)?.host

    @Test
    fun userinfoIsNotTheHost() {
        assertEquals("evil.example", host("https://bank.example@evil.example/login"))
        assertEquals("evil.example", host("https://bank.example:secret@evil.example/"))
    }

    @Test
    fun aBackslashEndsTheHostTheWayBrowsersParseIt() {
        assertEquals("evil.example", host("https://evil.example\\@bank.example/"))
    }

    @Test
    fun aLookalikeDomainShowsAsPunycode() {
        // Cyrillic "а" in place of Latin "a".
        assertEquals("xn--pypl-53dc.com", host("https://pаypаl.com/"))
    }

    @Test
    fun hostIsLowercased() {
        assertEquals("bank.example", host("HTTPS://BANK.Example/Path"))
    }

    @Test
    fun theOpenedUrlIsTheParsedOne() {
        val target = linkTargetOf("https://bank.example@evil.example/a b")!!
        assertEquals("evil.example", target.url.host)
        assertEquals("https://bank.example@evil.example/a%20b", target.url.toString())
    }

    @Test
    fun nonWebOrMalformedLinksAreRefused() {
        assertNull(linkTargetOf("javascript:alert(1)"))
        assertNull(linkTargetOf("mailto:a@example.com"))
        assertNull(linkTargetOf("https://"))
        assertNull(linkTargetOf("not a url"))
    }

    @Test
    fun addressShapedTextThatDisagreesNamesTheRealHost() {
        assertEquals("two.example", linkTextMismatch("https://one.example/", "https://two.example/"))
        assertEquals("bank.example.evil.example", linkTextMismatch("bank.example", "https://bank.example.evil.example/"))
        assertEquals("evil.example", linkTextMismatch("www.bank.example/login", "https://bank.example@evil.example/"))
    }

    @Test
    fun agreeingOrOrdinaryTextIsNotFlagged() {
        assertNull(linkTextMismatch("https://bank.example/login", "https://bank.example/other"))
        assertNull(linkTextMismatch("bank.example", "https://www.bank.example/"))
        assertNull(linkTextMismatch("bank.example", "https://login.bank.example/"))
        assertNull(linkTextMismatch("Click here", "https://evil.example/"))
        assertNull(linkTextMismatch("support@bank.example", "https://evil.example/"))
        assertNull(linkTextMismatch("https://one.example/", "mailto:a@two.example"))
    }
}
