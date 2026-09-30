package org.kysecurity.mail.signon

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.push.PairingData

class PendingPairingLinkTest {
    private val data = PairingData("s", "https://h", "https://h/r", "t", null, null, 0L)

    @Test fun takeIsSingleUse() {
        PendingPairingLink.set(data)
        assertEquals(data, PendingPairingLink.take())
        assertNull(PendingPairingLink.take())
    }

    @Test fun resetClears() {
        PendingPairingLink.set(data)
        PendingPairingLink.resetForNewSession()
        assertNull(PendingPairingLink.take())
    }
}
