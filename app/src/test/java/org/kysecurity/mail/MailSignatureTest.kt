package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class MailSignatureTest {

    private val on = MailSignature(enabled = true, text = "Ada")

    // --- The server's rules (KyPost-Server config/signatures.go) ---

    @Test
    fun twoThousandCharactersIsTheLimit() {
        assertNull(signatureProblem("a".repeat(2000)))
        assertEquals(SignatureProblem.TOO_LONG, signatureProblem("a".repeat(2001)))
    }

    /** The server counts runes: an emoji is one character, not two UTF-16 units. */
    @Test
    fun theLimitCountsCharactersNotUtf16Units() {
        assertNull(signatureProblem("😀".repeat(2000)))
        assertEquals(SignatureProblem.TOO_LONG, signatureProblem("😀".repeat(2001)))
    }

    @Test
    fun aWindowsLineEndingCountsAsOneCharacter() {
        assertNull(signatureProblem("a".repeat(1998) + "\r\n" + "a"))
    }

    @Test
    fun newlineAndTabAreAllowed() {
        assertNull(signatureProblem("Ada Lovelace\nAnalyst\tLondon\r\n"))
    }

    @Test
    fun controlCharactersAreRefused() {
        listOf("\u0000", "\u0007", "\u001B[31m", "a\rb", "\u007F", "\u0085").forEach {
            assertEquals(it, SignatureProblem.CONTROL_CHARACTER, signatureProblem("Ada$it"))
        }
    }

    @Test
    fun bidiOverrideAndIsolateCharactersAreRefused() {
        (0x202A..0x202E).plus(0x2066..0x2069).forEach {
            assertEquals(Integer.toHexString(it), SignatureProblem.CONTROL_CHARACTER, signatureProblem("Ada${it.toChar()}"))
        }
        // Marks, unlike overrides, do not reorder text and are used in ordinary RTL writing.
        assertNull(signatureProblem("Ada‏"))
    }

    // --- When it goes in ---

    @Test
    fun offByDefault() {
        assertEquals("", MailSignature(text = "Ada").textFor(ComposeKind.NEW))
    }

    @Test
    fun onItGoesOnNewMessagesRepliesAndForwards() {
        ComposeKind.entries.forEach { assertEquals("Ada", on.textFor(it)) }
    }

    @Test
    fun theReplySwitchControlsRepliesOnly() {
        val off = on.copy(onReply = false)
        assertEquals("", off.textFor(ComposeKind.REPLY))
        assertEquals("Ada", off.textFor(ComposeKind.NEW))
        assertEquals("Ada", off.textFor(ComposeKind.FORWARD))
    }

    @Test
    fun theForwardSwitchControlsForwardsOnly() {
        val off = on.copy(onForward = false)
        assertEquals("", off.textFor(ComposeKind.FORWARD))
        assertEquals("Ada", off.textFor(ComposeKind.NEW))
        assertEquals("Ada", off.textFor(ComposeKind.REPLY))
    }

    @Test
    fun turnedOffItGoesNowhere() {
        val off = on.copy(enabled = false)
        ComposeKind.entries.forEach { assertEquals("", off.textFor(it)) }
    }

    /** Whatever ended up in the file, refused text is never inserted. */
    @Test
    fun storedTextTheRulesRefuseIsNotInserted() {
        assertEquals("", on.copy(text = "Ada‮evil").textFor(ComposeKind.NEW))
    }

    // --- Where it goes (KyPost-Server docs/SIGNATURES.md) ---

    @Test
    fun noSignatureLeavesTheBodyAlone() {
        assertEquals("<div>quoted</div>", withSignature("<div>quoted</div>", ""))
        assertEquals("", withSignature("", "  "))
    }

    /** Typing line, blank line, signature. No `-- ` delimiter. */
    @Test
    fun aNewMessageGetsTheSignatureBelowABlankLine() {
        assertEquals("<br><br>Ada<br>Analyst", withSignature("", "Ada\nAnalyst"))
    }

    /** Typing line, blank, signature, blank, quote: the quote opens with its own blank line. */
    @Test
    fun theSignatureGoesAboveTheQuoteWithABlankLineEachSide() {
        val quote = "<br><br><div>bob wrote:</div><blockquote>hi</blockquote>"
        assertEquals("<br><br>Ada$quote", withSignature(quote, "Ada"))
    }

    @Test
    fun prefilledTextKeepsItsPlaceAndTheSignatureFollows() {
        assertEquals("Hello<br><br>Ada", withSignature("Hello", "Ada"))
    }

    /** The editor renders HTML; a signature is typed text and must never become markup. */
    @Test
    fun theSignatureIsEscaped() {
        assertEquals(
            "<br><br>&lt;b&gt;Ada&lt;/b&gt; &amp; &quot;co&#39;<br>&lt;script&gt;",
            withSignature("", "<b>Ada</b> & \"co'\r\n<script>"),
        )
    }
}
