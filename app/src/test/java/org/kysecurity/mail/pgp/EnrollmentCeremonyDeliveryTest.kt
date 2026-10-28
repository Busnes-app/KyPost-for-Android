package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** An envelope is opened only beside the delivery the server recorded, a v4 plaintext is sealed
 *  only when its one key is the recorded identity, and a retired v2/v3 delivery is never opened. */
class EnrollmentCeremonyDeliveryTest {

    @After fun cleanup() = EnrollmentSession.clear()

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
            delivery = DeliveryMetadata(ENVELOPE_VERSION_HPKE_KEYRING, FAKE_FINGERPRINT, 1L, listOf(FAKE_FINGERPRINT), listOf(FAKE_FINGERPRINT)),
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

    /** A retired delivery: the authentic v2/v3 vectors, and an honest HPKE seal under the retired
     *  binding, so a parser or opener that re-admitted either would be caught. */
    private fun retiredCases(): List<Pair<String, FakePorts>> {
        val vectors = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray.map { it.jsonObject["envelope"].toString() }
        return listOf(2, 3).flatMap { version ->
            val delivery = if (version == 3) {
                DeliveryMetadata(version, FAKE_FINGERPRINT, 1L, listOf(FAKE_FINGERPRINT), listOf(FAKE_FINGERPRINT))
            } else {
                DeliveryMetadata(version, FAKE_FINGERPRINT, null, null, null)
            }
            listOf(
                "v$version vector" to FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(vectors[version - 2], delivery))),
                "v$version as HPKE" to FakePorts(
                    fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(FakeEnrollmentKeys(), version = version), delivery)),
                ),
            )
        }
    }

    @Test
    fun aRetiredDeliveryIsRefusedWithoutOpeningSavingOrAcknowledging() = runBlocking {
        for ((name, ports) in retiredCases()) {
            ports.ceremony().run()

            assertEquals(name, EnrollmentUiState.Failed(FailureReason.RETIRED_ENVELOPE), ports.states.last())
            assertEquals("$name: never opened", 0, ports.keys.sharedSecretCalls)
            assertTrue(name, ports.sealer.received.isEmpty())
            assertTrue(name, ports.transport.reported.isEmpty())
            assertEquals(name, 0, ports.transport.durableReports)
            assertEquals(name, 0, ports.mailCache.clearCalls)
            assertFalse(name, EnrollmentSession.isHeld())
            assertEquals("$name: the agreement key is spent", 1, ports.keys.deleteCalls)
            assertEquals("$name: no second attempt", 1, ports.transport.fetchCalls)
        }
    }

    /** The refusal is keyed on the delivery record; a v2/v3 envelope beside a v4 record is still
     *  never opened. */
    @Test
    fun aRetiredEnvelopeBesideAnHpkeRecordIsMalformed() = runBlocking {
        val vector = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray[0].jsonObject["envelope"].toString()
        for (envelope in listOf(vector, sealEnvelope(FakeEnrollmentKeys(), version = 2))) {
            val ports = FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope, legacyDelivery())))

            ports.ceremony().run()

            ports.assertNothingSealed(FailureReason.ENVELOPE_MALFORMED)
            assertEquals(0, ports.keys.sharedSecretCalls)
        }
    }
}
