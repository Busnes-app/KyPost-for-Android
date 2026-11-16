package org.kysecurity.mail.push

import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.security.SpkiPinner
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * What a stored pin set means once it reaches OkHttp.
 *
 * A set written today holds ONE leaf pin. It briefly held the whole chain instead, to survive
 * certificate renewal, and that is the wrong fix for a real problem: `CertificatePinner` passes
 * when ANY chain member matches ANY configured pin, so pinning an issuer admits every certificate
 * that issuer signs. A window of previously observed leaves was the second wrong fix — a key this
 * device has never seen cannot be learned from a connection the pin itself rejects. Renewal is
 * handled by the user re-trusting the server, which does not cost them the mailbox.
 *
 * These pin down: every stored pin reaches the host, nothing unobserved is admitted, and an empty
 * pin set — which `CertificatePinner` would pass vacuously — cannot be built at all.
 */
class TlsChainPinningTest {

    private val host = "relay.example.com"

    /** A real 32-byte SHA-256 pin. Repeating one base64 character does not round-trip: the trailing
     *  bits must be zero, so OkHttp normalises the last character and the constant stops matching. */
    private fun pin(seed: Byte): String =
        "sha256/" + java.util.Base64.getEncoder().encodeToString(ByteArray(32) { seed })

    private val currentLeaf = pin(1)
    private val previousLeaf = pin(2)

    @Test
    fun everyStoredPinIsRegisteredForTheHost() {
        val client = pairingHttpClient(PinPosture.Pinned(host, setOf(currentLeaf, previousLeaf)))

        val matched = client.certificatePinner.findMatchingPins(host)

        // Both, not one: `add` was called per pin. Registering only the first would collapse the
        // rotation window and make a renewal unverifiable.
        assertEquals(2, matched.size, "every stored leaf pin must be registered for the host")
    }

    /** Multiple pins for one host are all honoured by OkHttp, and a certificate this device has
     *  never observed is not among them. This is the shape a legacy whole-chain set has until
     *  [PushSyncCoordinator.refreshTlsPin] replaces it with the single leaf. */
    @Test
    fun onlyObservedCertificatesAreEverAdmitted() {
        val client = pairingHttpClient(PinPosture.Pinned(host, setOf(currentLeaf, previousLeaf)))

        // Pin.toString() is the "sha256/BASE64" form CertificatePinner.pin() produces.
        val pinned = client.certificatePinner.findMatchingPins(host).map { it.toString() }

        assertTrue(pin(9) !in pinned, "a certificate this device never saw is genuinely unknown")
        assertTrue(previousLeaf in pinned, "the leaf being rotated away from must still validate")
        assertTrue(currentLeaf in pinned, "and so must the one rotated to")
    }

    @Test
    fun aPinnedPostureWithNoPinsIsRefused() {
        // CertificatePinner passes vacuously when no pin is configured for the host, so building
        // this client would silently unpin the connection.
        assertFailsWith<IllegalArgumentException> {
            pairingHttpClient(PinPosture.Pinned(host, emptySet()))
        }
    }

    @Test
    fun aTlsPinWithNoPinsCannotBeConstructed() {
        assertFailsWith<IllegalArgumentException> { TlsPin(host, emptySet()) }
    }

    /** TofuWindow is still the only unpinned posture, and only before a first pairing. */
    @Test
    fun theTofuWindowRemainsUnpinned() {
        val client = pairingHttpClient(PinPosture.TofuWindow)

        assertEquals(0, client.certificatePinner.findMatchingPins(host).size)
    }
}
