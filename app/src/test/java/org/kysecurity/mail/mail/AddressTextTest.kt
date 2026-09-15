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
    fun displayTextDropsBidiOverrides() {
        assertEquals("moc.elpmaxe@a", displayHeaderText("\u202Emoc.elpmaxe@a\u202C"))
    }

    @Test
    fun valueWithNoAddressYieldsEmpty() {
        assertEquals("", addressFromHeader("Unknown sender"))
        assertEquals("", addressFromHeader(""))
    }
}
