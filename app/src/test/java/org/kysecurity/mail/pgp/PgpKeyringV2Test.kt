package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.*
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.After
import org.junit.Assert.*
import org.junit.Test

/** The owner-specified v2 shape carries two explicitly active certificate classes. */
class PgpKeyringV2Test {
    @After fun clear() = EnrollmentSession.clear()

    @Test fun bothCertificateClassesRemainReadableAndV4RemainsTheSendDefault() {
        val bytes = ringV2().toString().toByteArray()
        val parsed = requireNotNull(parsePgpKeyring(bytes, v6Fingerprint))
        assertEquals(mapOf("v4" to v4Fingerprint, "v6" to v6Fingerprint), parsed.activeFingerprints)
        assertArrayEquals(bytes, parsed.original)
        EnrollmentSession.putKeyring(parsed)
        for (prefix in listOf("v4-pqc", "v6-pqc")) {
            val decrypted = EnrollmentSession.withDecryptionKeys { provider ->
                PgpDecryptor.decrypt(provider, fixture("$prefix.msg.asc"), emptyList(), refuseLegacy = true)
            }
            assertTrue("$prefix: $decrypted", decrypted is DecryptResult.Ok)
            assertEquals(fixture("message.txt"), String((decrypted as DecryptResult.Ok).plaintext))
            decrypted.plaintext.fill(0)
        }
        val reopened = requireNotNull(reopenPgpKeyring(bytes))
        assertEquals(v4Fingerprint, reopened.activeFingerprint)
        assertArrayEquals(bytes, reopened.original)
        reopened.wipe()
    }

    @Test fun eitherActiveClassMayBeOmittedButAnInactiveOrWrongVersionKeyIsRefused() {
        for (version in listOf("v4", "v6")) {
            val fingerprint = if (version == "v4") v4Fingerprint else v6Fingerprint
            val ring = ringV2(mapOf(version to fingerprint))
            assertNotNull(parsePgpKeyring(ring.toString().toByteArray(), fingerprint))
            val other = if (version == "v4") v6Fingerprint else v4Fingerprint
            assertNull(parsePgpKeyring(ring.toString().toByteArray(), other))
        }
        for (active in listOf(emptyMap(), mapOf("v5" to v4Fingerprint), mapOf("v4" to v6Fingerprint), mapOf("v6" to v4Fingerprint), mapOf("v6" to "A".repeat(64)))) {
            assertNull(reopenPgpKeyring(ringV2(active).toString().toByteArray()))
        }
        val withOldField = JsonObject(ringV2() + ("activeFingerprint" to JsonPrimitive(v4Fingerprint)))
        assertNull(reopenPgpKeyring(withOldField.toString().toByteArray()))
        val missingMember = JsonObject(ringV2() + ("keys" to JsonArray(ringV2().getValue("keys").jsonArray.take(1))))
        assertNull(reopenPgpKeyring(missingMember.toString().toByteArray()))
    }

    @Test fun largerV2RingIsValidatedSealedAndReopenedWithoutReserializing() = runBlocking {
        val small = ringV2().toString()
        val bytes = (small.dropLast(1) + " ".repeat(160 * 1024) + "}").toByteArray()
        val sealer = FakeVaultSealer()
        assertEquals(KeyringImportOutcome.Imported, importKeyring(bytes, v6Fingerprint, 6,
            FakeVaultOpener(outcome = OpenOutcome.NotEnrolled), { null }, sealer, {}))
        assertArrayEquals(bytes, sealer.received.single())
        assertEquals(VaultRecordKind.KEYRING, sealer.kinds.single())
        assertEquals(EnrollmentReport.Keyring(3, v6Fingerprint, 6), sealer.acks.single())
        EnrollmentSession.clear()
        assertTrue(installOpenedMaterial(VaultRecordKind.KEYRING, bytes))
        assertEquals(setOf(v4Fingerprint, v6Fingerprint), EnrollmentSession.withKeyring { it.activeFingerprints.values.toSet() })
        val tooLarge = (small + " ".repeat(512 * 1024)).toByteArray()
        assertNull(reopenPgpKeyring(tooLarge))
    }

    @Test fun identicalRingReplayRefreshesTheExactDeliveryAcknowledgement() = runBlocking {
        val bytes = ringV2().toString().toByteArray()
        EnrollmentSession.putKeyring(requireNotNull(parsePgpKeyring(bytes, v4Fingerprint)))
        val sealer = FakeVaultSealer()
        assertEquals(KeyringImportOutcome.Replayed, importKeyring(bytes, v6Fingerprint, 6,
            FakeVaultOpener(outcome = OpenOutcome.Opened), { VaultRecordKind.KEYRING }, sealer, {}))
        assertTrue(sealer.received.isEmpty())
        assertEquals(listOf(EnrollmentReport.Keyring(3, v6Fingerprint, 6)), sealer.replayedAcks)
    }

    companion object {
        fun fixture(name: String) = String(SharedFixtures.bytes("openpgp-v6/$name"))
        private fun secret(prefix: String): PGPSecretKeyRing = PGPSecretKeyRingCollection(
            PGPUtil.getDecoderStream(fixture("$prefix.sec.asc").byteInputStream()), BcKeyFingerprintCalculator(),
        ).keyRings.next()
        val v4Fingerprint = PgpFingerprint.of(secret("v4-pqc").publicKey).replace(" ", "")
        val v6Fingerprint = PgpFingerprint.of(secret("v6-pqc").publicKey).replace(" ", "")
        fun ringV2(active: Map<String, String> = mapOf("v4" to v4Fingerprint, "v6" to v6Fingerprint)): JsonObject = buildJsonObject {
            put("format", "kypost-pgp-keyring-v2")
            put("materialGeneration", 3)
            put("active", JsonObject(active.mapValues { JsonPrimitive(it.value) }))
            put("keyFingerprints", JsonArray(listOf("v4-pqc", "v6-pqc").flatMap { prefix ->
                secret(prefix).publicKeys.asSequence().map { JsonPrimitive(PgpFingerprint.of(it).replace(" ", "")) }.toList()
            }))
            put("keys", JsonArray(listOf("v4-pqc", "v6-pqc").map { prefix -> buildJsonObject {
                put("fingerprint", PgpFingerprint.of(secret(prefix).publicKey).replace(" ", ""))
                put("privateKey", fixture("$prefix.sec.asc"))
            } }))
        }
    }
}
