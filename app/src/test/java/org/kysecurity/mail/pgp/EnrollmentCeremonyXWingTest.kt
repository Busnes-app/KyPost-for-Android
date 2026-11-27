package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class EnrollmentCeremonyXWingTest {
    @After fun clear() = EnrollmentSession.clear()

    private val fingerprint = PgpKeyringV2Test.v6Fingerprint
    private val ring = PgpKeyringV2Test.ringV2()
    private val delivery = DeliveryMetadata(6, fingerprint, 3,
        listOf(PgpKeyringV2Test.v4Fingerprint, fingerprint), ring.getValue("keyFingerprints").jsonArray.map { it.jsonPrimitive.content })

    private class Keys : EnrollmentKeys {
        val seed = ByteArray(32) { 0x65 }
        var deletes = 0
        var opens = 0
        var cancelled = false
        override fun newKeyPair() = true
        override fun rawPublicKey() = xwingPublicKey(seed)
        override fun encodedPublicKey() = Base64.getEncoder().encodeToString(rawPublicKey())
        override fun sharedSecret(epk: ByteArray): ByteArray? = error("X-Wing must not use legacy ECDH")
        override suspend fun openEnvelope(fields: DeviceEnvelopeFields, info: ByteArray): ByteArray? {
            opens++
            if (cancelled) throw EnrollmentAuthenticationCancelled()
            return xwingOpen(seed, fields, info)
        }
        override fun deleteKeyPair(): Boolean { deletes++; seed.fill(0); return true }
    }

    private suspend fun run(delivery: DeliveryMetadata? = this.delivery, plaintext: String = ring.toString(),
        cancel: Boolean = false, aadId: String = "dev-1", mutate: (DeviceEnvelopeFields) -> Unit = {}) : Triple<FakeEnrollmentTransport, FakeVaultSealer, List<EnrollmentUiState>> {
        val keys = Keys().also { it.cancelled = cancel }
        val fields = xwingSeal(keys.rawPublicKey(), deviceEnvelopeAad(6, aadId, fingerprint), plaintext.toByteArray()).also(mutate)
        val json = buildJsonObject {
            put("v", 6); put("alg", XWING_ENVELOPE_ALG)
            put("enc", Base64.getEncoder().encodeToString(fields.epk)); put("ct", Base64.getEncoder().encodeToString(fields.ct))
        }.toString()
        val transport = FakeEnrollmentTransport(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(json, delivery)))
        val sealer = FakeVaultSealer()
        val states = mutableListOf<EnrollmentUiState>()
        val ceremony = EnrollmentCeremony(FakeIdentitySource(IdentityCheck.ClientProtected(fingerprint)), transport, keys,
            sealer, FakeVaultOpener(outcome = OpenOutcome.NotEnrolled), FakeDecryptedMailCache(), FakeEnrollmentClock(), { false }, { true }, { states += it })
        ceremony.run()
        if (!cancel) assertEquals(1, keys.deletes)
        if (cancel) { assertEquals(0, keys.deletes); ceremony.teardown() }
        return Triple(transport, sealer, states)
    }

    @Test fun v2RingIsDurableBeforeItsExactV6Acknowledgement() = runBlocking {
        val (transport, sealer, states) = run()
        assertEquals(EnrollmentUiState.Enrolled, states.last())
        val ack = EnrollmentReport.Keyring(3, fingerprint, 6)
        assertEquals(listOf(ack), transport.reported)
        assertEquals(listOf(ack), sealer.acks)
        assertEquals(listOf(VaultRecordKind.KEYRING), sealer.kinds)
        assertArrayEquals(ring.toString().toByteArray(), sealer.received.single())
    }

    @Test fun missingMismatchedOrWrongGenerationDeliveryNeverInstalls() = runBlocking {
        for (metadata in listOf(null, delivery.copy(version = 5), delivery.copy(fingerprint = "A".repeat(64)), delivery.copy(materialGeneration = 4), delivery.copy(primaryFingerprints = emptyList()))) {
            val (transport, sealer, states) = run(delivery = metadata)
            assertTrue(states.last() is EnrollmentUiState.Failed)
            assertTrue(sealer.received.isEmpty())
            assertTrue(transport.reported.isEmpty())
        }
    }

    @Test fun wrongDeviceOrTamperedCiphertextNeverSealsOrAcknowledges() = runBlocking {
        val cases = listOf(run(aadId = "another-device"), run(mutate = { it.ct[0] = (it.ct[0].toInt() xor 1).toByte() }))
        for ((transport, sealer, states) in cases) {
            assertEquals(EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN), states.last())
            assertTrue(sealer.received.isEmpty()); assertTrue(transport.reported.isEmpty())
        }
    }

    @Test fun cancellingSeedAuthenticationKeepsTheCeremonyRetryable() = runBlocking {
        val (transport, sealer, states) = run(cancel = true)
        assertEquals(EnrollmentUiState.ReadyToFinish, states.last())
        assertTrue(sealer.received.isEmpty()); assertTrue(transport.reported.isEmpty())
    }

    @Test fun generationZeroV6StillAcceptsOneLegacyPrivateKey() = runBlocking {
        val (transport, sealer, states) = run(delivery.copy(materialGeneration = 0, primaryFingerprints = null, keyFingerprints = null),
            plaintext = PgpKeyringV2Test.fixture("v6-pqc.sec.asc"))
        assertEquals(EnrollmentUiState.Enrolled, states.last())
        assertEquals(listOf(VaultRecordKind.LEGACY_ARMOR), sealer.kinds)
        assertEquals(listOf(EnrollmentReport.Legacy), transport.reported)
    }

    @Test fun wrapKeyValidationAcceptsPerUseHardwareKeysAndRejectsTimedOrSoftwareKeys() {
        val strongBox = android.security.keystore.KeyProperties.SECURITY_LEVEL_STRONGBOX
        val tee = android.security.keystore.KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT
        val software = android.security.keystore.KeyProperties.SECURITY_LEVEL_SOFTWARE
        val auth = XWingEnrollmentKeys.AUTHENTICATORS

        for (level in listOf(strongBox, tee)) {
            for (duration in listOf(-1, 0)) {
                assertTrue("hardware level=$level duration=$duration must pass",
                    XWingEnrollmentKeys.isValidWrapKeyInfo(level, 256, true, duration, auth))
            }
        }
        assertFalse(XWingEnrollmentKeys.isValidWrapKeyInfo(software, 256, true, -1, auth))
        assertFalse(XWingEnrollmentKeys.isValidWrapKeyInfo(tee, 256, true, 1, auth))
        assertFalse(XWingEnrollmentKeys.isValidWrapKeyInfo(tee, 256, false, -1, auth))
        assertFalse(XWingEnrollmentKeys.isValidWrapKeyInfo(tee, 128, true, -1, auth))
        assertFalse(XWingEnrollmentKeys.isValidWrapKeyInfo(tee, 256, true, -1,
            android.security.keystore.KeyProperties.AUTH_DEVICE_CREDENTIAL))
    }
}
