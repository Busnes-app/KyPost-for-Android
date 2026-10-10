package org.kysecurity.mail.mail

import org.junit.Assert.assertEquals
import org.junit.Test

// The real address is the LAST angle-addr; vectors are shared with the webmail and Linux clients.
class AddressTextTest {
    @Test
    fun ordinaryDisplayNameAndAddress() {
        assertEquals("bob@corp.com", addressFromHeader("Bob <bob@corp.com>"))
    }

    @Test
    fun addressPlantedInTheDisplayNameIsIgnored() {
        assertEquals("bob@corp.com", addressFromHeader("\"evil@attacker.tld\" <bob@corp.com>"))
    }

    @Test
    fun realAddressWinsOverAMimickingDisplayName() {
        assertEquals("evil@attacker.tld", addressFromHeader("\"Bob <bob@corp.com>\" <evil@attacker.tld>"))
    }

    @Test
    fun bareAddressPassesThrough() {
        assertEquals("bob@corp.com", addressFromHeader("bob@corp.com"))
    }

    @Test
    fun commaInsideAQuotedDisplayName() {
        assertEquals("bob@corp.com", addressFromHeader("\"a, b\" <bob@corp.com>"))
    }

    @Test
    fun displayTextFlattensLineBreaksThatWouldForgeALabelledLine() {
        assertEquals(
            "\"Alice Cc: ceo@example.com\" <a@example.com>",
            displayHeaderText("\"Alice\r\nCc: ceo@example.com\" <a@example.com>"),
        )
    }

    @Test
    fun displayTextFlattensUnicodeLineAndParagraphSeparators() {
        assertEquals("Alice Cc: ceo@example.com", displayHeaderText("Alice\u2028Cc: ceo@example.com"))
        assertEquals("Alice Cc: ceo@example.com", displayHeaderText("Alice\u2029Cc: ceo@example.com"))
    }

    @Test
    fun displayTextDropsBidiOverrides() {
        assertEquals("moc.elpmaxe@a", displayHeaderText("\u202Emoc.elpmaxe@a\u202C"))
    }

    @Test
    fun replyAllDropsEveryOwnAddressCaseInsensitively() {
        val recipients = replyAllRecipients(
            sender = "Bob <bob@example.com>",
            to = listOf("Me <ME@example.com>", "carol@example.com"),
            cc = listOf("alias@example.com", "Bob <BOB@example.com>"),
            own = listOf("me@example.com", "Alias@Example.com"),
        )

        assertEquals(listOf("bob@example.com", "carol@example.com"), recipients)
    }

    /** Reply All on one's own sent mail goes to the people it was sent to. */
    @Test
    fun replyAllToOwnSentMailKeepsTheOtherRecipients() {
        val recipients = replyAllRecipients(
            sender = "me@example.com",
            to = listOf("carol@example.com"),
            cc = emptyList(),
            own = listOf("me@example.com"),
        )

        assertEquals(listOf("carol@example.com"), recipients)
    }

    /** A note to self has nobody else to reply to; an empty To would be worse than self. */
    @Test
    fun replyAllWithOnlyOwnAddressesKeepsThem() {
        val recipients = replyAllRecipients(
            sender = "me@example.com",
            to = listOf("me@example.com"),
            cc = emptyList(),
            own = listOf("me@example.com"),
        )

        assertEquals(listOf("me@example.com"), recipients)
    }

    @Test
    fun valueWithNoAddressYieldsEmpty() {
        assertEquals("", addressFromHeader("Unknown sender"))
        assertEquals("", addressFromHeader(""))
    }
}
