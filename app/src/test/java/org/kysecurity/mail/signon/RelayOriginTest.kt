package org.kysecurity.mail.signon

import org.junit.Assert.assertEquals
import org.junit.Test

class RelayOriginTest {
    @Test fun trimsWhitespaceOnly() {
        assertEquals("https://Mail.Example.com/x/", typedRelayUrl("  https://Mail.Example.com/x/\n"))
    }

    @Test fun optionKeyIsTheKyAuthContract() {
        assertEquals("org.kysecurity.identity.origin", KyIdentitySignOn.OPTION_ORIGIN)
    }
}
