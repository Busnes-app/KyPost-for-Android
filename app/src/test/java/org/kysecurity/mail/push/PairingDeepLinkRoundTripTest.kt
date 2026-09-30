package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PairingDeepLinkRoundTripTest {
    private fun pairing(pin: String?) = PairingData(
        subscriberId = "sub 1&x=y",
        serverUrl = "https://server.example.com",
        registrationUrl = "https://server.example.com/api/notifications/native/register",
        pairingToken = "tok/+=?#",
        deviceId = null,
        deviceSecret = null,
        pairedAtEpochMs = 5L,
        spkiPin = pin,
    )

    @Test
    fun roundTripsThroughTheParser() {
        val link = pairingDeepLink(pairing("sha256///////////////////////////////////////////8="))
        val parsed = (NativePairingDeepLinkParser.parse(link, 5L) as PairingParseResult.Success).pairing
        assertEquals("sub 1&x=y", parsed.subscriberId)
        assertEquals("https://server.example.com", parsed.serverUrl)
        assertEquals("https://server.example.com/api/notifications/native/register", parsed.registrationUrl)
        assertEquals("tok/+=?#", parsed.pairingToken)
        assertEquals("sha256///////////////////////////////////////////8=", parsed.spkiPin)
    }

    @Test
    fun omitsPinWhenAbsent() {
        val link = pairingDeepLink(pairing(null))
        assertTrue("pin=" !in link)
        val parsed = (NativePairingDeepLinkParser.parse(link, 5L) as PairingParseResult.Success).pairing
        assertNull(parsed.spkiPin)
    }
}
