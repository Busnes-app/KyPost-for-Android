package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Live v3 enrollment: a keyring envelope is opened under the v3 domain, validated against the
 * delivery the server recorded, imported through [importKeyring], and acknowledged with the
 * generation and fingerprint. Contract: KyPost-Server #210 (`36cc6d6`), #212 (`c9c1e5e`).
 */
class EnrollmentCeremonyKeyringTest {

    private val ring = SharedFixtures.keyring()["ring"]!!.jsonObject
    private val ringJson = ring.toString()
    private val active = ring["activeFingerprint"]!!.jsonPrimitive.content
    private val members = listOf("5F117951610CAF01500FA059CDE63F0EBEC934A2", "3DA91B24C0BFAB595BEFE10D85ED094DCCE10615")
    private val inventory = members + listOf("F8FF743DD85DDE3D427E8BA25CA9134FFE0FF9F4", "3C85B240C5591A07008A3665F96FF568D839A072")

    private val delivery = DeliveryMetadata(
        version = ENVELOPE_VERSION_KEYRING,
        fingerprint = active,
        materialGeneration = 2L,
        primaryFingerprints = members,
        keyFingerprints = inventory,
    )

    @After fun cleanup() = EnrollmentSession.clear()

    private fun ports(
        delivery: DeliveryMetadata? = this.delivery,
        reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    ): FakePorts {
        val probe = FakeEnrollmentKeys()
        val envelope = sealEnvelope(probe, aadFingerprint = active, plaintext = ringJson, version = ENVELOPE_VERSION_KEYRING)
        return FakePorts(
            identityResult = IdentityCheck.ClientProtected(active),
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope, delivery)),
            reportResult = reportResult,
        )
    }

    @Test
    fun aMatchingKeyringDeliveryIsImportedAndAcknowledged() = runBlocking {
        val ports = ports()

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(VaultRecordKind.KEYRING), ports.sealer.kinds)
        assertArrayEquals("the original bytes are sealed", ringJson.toByteArray(Charsets.UTF_8), ports.sealer.received.single())
        val ack = EnrollmentReport.Keyring(materialGeneration = 2L, fingerprint = active)
        assertEquals("stored beside the record for the worker", listOf(ack), ports.sealer.acks)
        assertEquals("acknowledged with the delivery's values, never the bare boolean", listOf(ack), ports.transport.reported)
        assertEquals(1, ports.mailCache.clearCalls)
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals(2L, EnrollmentSession.withKeyring { it.materialGeneration })
    }

    /** The ring inside the envelope must be the one the server says it delivered. Same active
     *  key at another generation is a different ring; nothing is sealed and nothing reported. */
    @Test
    fun aRingAtAnotherGenerationThanTheDeliveryIsRejected() = runBlocking {
        val ports = ports(delivery = delivery.copy(materialGeneration = 3L))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.KEYRING_REJECTED), ports.states.last())
        assertTrue(ports.sealer.kinds.isEmpty())
        assertTrue(ports.transport.reported.isEmpty())
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aRingWhoseInventoryDiffersFromTheDeliveryIsRejected() = runBlocking {
        val ports = ports(delivery = delivery.copy(keyFingerprints = inventory.dropLast(1)))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.KEYRING_REJECTED), ports.states.last())
        assertTrue(ports.sealer.kinds.isEmpty())
    }

    @Test
    fun aRingWhoseMembersDifferFromTheDeliveryIsRejected() = runBlocking {
        val ports = ports(delivery = delivery.copy(primaryFingerprints = members.take(1)))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.KEYRING_REJECTED), ports.states.last())
        assertTrue(ports.sealer.kinds.isEmpty())
    }

    /** A v3 envelope from a server that recorded no delivery cannot be validated, so it is not
     *  opened as anything. */
    @Test
    fun aKeyringEnvelopeWithoutDeliveryMetadataIsMalformed() = runBlocking {
        val ports = ports(delivery = null)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.ENVELOPE_MALFORMED), ports.states.last())
        assertTrue(ports.sealer.kinds.isEmpty())
    }

    /** A legacy delivery record beside a v3 envelope is a server the client does not understand. */
    @Test
    fun aKeyringEnvelopeWithALegacyDeliveryRecordIsMalformed() = runBlocking {
        val ports = ports(delivery = delivery.copy(version = ENVELOPE_VERSION_LEGACY, materialGeneration = null))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.ENVELOPE_MALFORMED), ports.states.last())
        assertTrue(ports.sealer.kinds.isEmpty())
    }

    /** The import is durable before the acknowledgement; a refused acknowledgement means the
     *  account moved on. Repeating the same claim cannot help, so nothing is queued, and the
     *  screen must not say it worked: the server refused to record this device as enrolled. */
    @Test
    fun aRefusedAcknowledgementIsATerminalFailureWithoutRetry() = runBlocking {
        val ports = ports(reportResult = EnrollmentCallResult.Conflict)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.ACKNOWLEDGEMENT_REFUSED), ports.states.last())
        assertEquals("the record is durable; the copy must not claim otherwise", listOf(VaultRecordKind.KEYRING), ports.sealer.kinds)
        assertEquals(0, ports.transport.durableReports)
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aDroppedAcknowledgementIsRetriedDurably() = runBlocking {
        val ports = ports(reportResult = EnrollmentCallResult.Failed("offline"))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, ports.transport.durableReports)
    }

    /** A v2 envelope still takes the legacy path and the bare boolean, untouched by any of this. */
    @Test
    fun aLegacyEnvelopeStillSealsArmorAndReportsTheBoolean() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.Envelope(
                    sealEnvelope(probe, plaintext = TestPgpPrivateKey.ARMORED_PRIVATE),
                    DeliveryMetadata(ENVELOPE_VERSION_LEGACY, FAKE_FINGERPRINT, null, null, null),
                ),
            ),
        )

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(VaultRecordKind.LEGACY_ARMOR), ports.sealer.kinds)
        assertEquals(listOf<EnrollmentReport.Keyring?>(null), ports.sealer.acks)
        assertEquals(listOf(EnrollmentReport.Legacy), ports.transport.reported)
    }
}
