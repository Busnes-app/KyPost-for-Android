package org.kysecurity.mail.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class RelayOriginTest {
    @Test fun stripsPathAndTrailingSlash() {
        assertEquals("https://mail.example.com", relayOrigin("  https://mail.example.com/x/\n"))
    }

    @Test fun lowercasesHost() {
        assertEquals("https://mail.example.com", relayOrigin("https://Mail.EXAMPLE.com"))
    }

    @Test fun dropsExplicit443() {
        assertEquals("https://mail.example.com", relayOrigin("https://mail.example.com:443/"))
    }

    @Test fun keepsNonDefaultPort() {
        assertEquals("https://mail.example.com:8443", relayOrigin("https://mail.example.com:8443/a"))
    }

    @Test fun punycodesIdn() {
        assertEquals("https://xn--bcher-kva.example", relayOrigin("https://bücher.example/"))
    }

    @Test fun refusesHttp() {
        assertNull(relayOrigin("http://mail.example.com"))
    }

    @Test fun optionKeyIsTheKyAuthContract() {
        assertEquals("org.kysecurity.identity.origin", KyIdentitySignOn.OPTION_ORIGIN)
    }
}
