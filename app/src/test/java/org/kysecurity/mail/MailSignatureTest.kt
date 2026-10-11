package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class MailSignatureTest {

    @Test
    fun noSignatureLeavesTheBodyAlone() {
        assertEquals("<div>quoted</div>", withSignature("<div>quoted</div>", ""))
        assertEquals("", withSignature("", "  "))
    }

    @Test
    fun aNewMessageGetsTheDelimitedSignature() {
        assertEquals("<br><br>-- <br>Ada<br>Analyst", withSignature("", "Ada<br>Analyst"))
    }

    @Test
    fun theSignatureGoesAboveTheQuote() {
        val quote = "<br><br><div>bob wrote:</div><blockquote>hi</blockquote>"
        val body = withSignature(quote, "Ada")
        assertTrue(body.endsWith(quote))
        assertTrue(body.indexOf("Ada") < body.indexOf("<blockquote>"))
    }
}
