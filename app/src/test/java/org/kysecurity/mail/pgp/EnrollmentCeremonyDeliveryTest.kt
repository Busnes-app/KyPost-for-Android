package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** An envelope is opened only beside the delivery the server recorded, and a v2 plaintext is sealed
 *  only when its one key is the recorded identity. */
class EnrollmentCeremonyDeliveryTest {

    private fun ports(
        delivery: DeliveryMetadata? = legacyDelivery(),
        plaintext: String = FAKE_PLAINTEXT,
        identity: String = FAKE_FINGERPRINT,
    ): FakePorts {
        val envelope = sealEnvelope(FakeEnrollmentKeys(), plaintext = plaintext)
        return FakePorts(
            identityResult = IdentityCheck.ClientProtected(identity),
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope, delivery)),
        )
    }

    private fun FakePorts.assertNothingSealed(reason: FailureReason) {
        assertEquals(EnrollmentUiState.Failed(reason), states.last())
        assertTrue(sealer.received.isEmpty())
        assertTrue(transport.reported.isEmpty())
        assertEquals(1, keys.deleteCalls)
    }

    @Test
    fun aLegacyEnvelopeWithoutADeliveryRecordSealsNothing() = runBlocking {
        val ports = ports(delivery = null)

        ports.ceremony().run()

        ports.assertNothingSealed(FailureReason.ENVELOPE_MALFORMED)
    }

    @Test
    fun aDeliveryRecordOfAnotherVersionSealsNothing() = runBlocking {
        val ports = ports(
            delivery = DeliveryMetadata(ENVELOPE_VERSION_KEYRING, FAKE_FINGERPRINT, 1L, listOf(FAKE_FINGERPRINT), listOf(FAKE_FINGERPRINT)),
        )

        ports.ceremony().run()

        ports.assertNothingSealed(FailureReason.ENVELOPE_MALFORMED)
    }

    @Test
    fun aDeliveryRecordForAnotherIdentitySealsNothing() = runBlocking {
        val ports = ports(delivery = legacyDelivery(TestPgpKey.FINGERPRINT.filterNot { it.isWhitespace() }))

        ports.ceremony().run()

        ports.assertNothingSealed(FailureReason.ENVELOPE_MALFORMED)
    }

    @Test
    fun aLegacyKeyOtherThanTheIdentitySealsNothing() = runBlocking {
        val ports = ports(plaintext = TestPgpSecondKey.ARMORED_PRIVATE)

        ports.ceremony().run()

        ports.assertNothingSealed(FailureReason.KEYRING_REJECTED)
    }

    @Test
    fun aLegacyPlaintextHoldingASecondKeySealsNothing() = runBlocking {
        val rings = listOf(TestPgpPrivateKey.ARMORED_PRIVATE, TestPgpSecondKey.ARMORED_PRIVATE)
            .map { orderedSecretKeyRings(it.byteInputStream())!!.single() }
        val ports = ports(plaintext = serializeSecretKeyRings(rings)!!.toString(Charsets.UTF_8))

        ports.ceremony().run()

        ports.assertNothingSealed(FailureReason.KEYRING_REJECTED)
    }

    /** Bootstrap reports the fingerprint spaced; the server records it bare. */
    @Test
    fun theSpacedIdentityFormMatchesTheRecordedDelivery() = runBlocking {
        val ports = ports(identity = TestPgpPrivateKey.FINGERPRINT)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(VaultRecordKind.LEGACY_ARMOR), ports.sealer.kinds)
    }
}
