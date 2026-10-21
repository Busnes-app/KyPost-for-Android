package org.kysecurity.mail.security

import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.push.DeregisterResult
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.TlsPin

/** The deregister client is built from a pin captured before the wipe clears the pairing. */
class WipeDeregisterPinningTest {

    @Test
    fun noCapturedPinMeansNoDeregisterClient() {
        // Fails closed. A pairing with no captured pin is `TlsPinState.Lost`, which every ordinary
        // request already refuses; the wipe must not be the one caller that downgrades instead.
        assertNull(SecurityWipe.pinnedDeregisterClient(null))
    }

    @Test
    fun aCapturedPinProducesAClient() {
        val client = SecurityWipe.pinnedDeregisterClient(
            TlsPin(host = "relay.example.com", spkiSha256 = setOf("sha256/${"A".repeat(43)}=")),
        )
        assertNotNull("a captured pin must still produce a working deregister path", client)
    }

    private val pin = TlsPin(host = "relay.example.com", spkiSha256 = setOf("sha256/${"A".repeat(43)}="))
    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    /** An unpair that escalates to a wipe has already deregistered and cleared the pin with the
     *  pairing. The wipe used to log "no TLS pin was captured" for it, as if the unpair had refused. */
    @Test
    fun nothingPairedMeansNothingToDeregister() = kotlinx.coroutines.runBlocking {
        var sent = false
        val result = SecurityWipe.deregisterForWipe(pairing = null, pin = null) { _, _ -> sent = true; DeregisterResult.Success }
        assertNull(result)
        org.junit.Assert.assertFalse(sent)
    }

    @Test
    fun aPairingWithoutAPinIsStillRefused() = kotlinx.coroutines.runBlocking {
        var sent = false
        val result = SecurityWipe.deregisterForWipe(pairing, pin = null) { _, _ -> sent = true; DeregisterResult.Success }
        org.junit.Assert.assertTrue(result is DeregisterResult.Error)
        org.junit.Assert.assertFalse("the device secret must not go out unpinned", sent)
    }

    @Test
    fun aPinnedPairingIsDeregistered() = kotlinx.coroutines.runBlocking {
        val result = SecurityWipe.deregisterForWipe(pairing, pin) { _, sentFor ->
            org.junit.Assert.assertEquals(pairing, sentFor)
            DeregisterResult.Success
        }
        org.junit.Assert.assertEquals(DeregisterResult.Success, result)
    }
}
