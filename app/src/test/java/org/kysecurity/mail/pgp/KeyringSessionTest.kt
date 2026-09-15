package org.kysecurity.mail.pgp

import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The session holding a validated keyring: every member decrypts, only the active member signs. */
class KeyringSessionTest {

    private val fixture = SharedFixtures.keyring()
    private val ringBytes = fixture["ring"]!!.jsonObject.toString().toByteArray(Charsets.UTF_8)
    private val active = fixture["ring"]!!.jsonObject["activeFingerprint"]!!.jsonPrimitive.content
    private val historicalPlaintext = fixture["plaintext"]!!.jsonPrimitive.content

    @After fun cleanup() = EnrollmentSession.clear()

    private fun hold() = EnrollmentSession.putKeyring(requireNotNull(parsePgpKeyring(ringBytes, active)))

    @Test
    fun everyRetainedMemberDecryptsIncludingForAHiddenRecipient() {
        hold()
        for (field in listOf("ciphertext", "hiddenCiphertext")) {
            val armored = fixture[field]!!.jsonPrimitive.content
            val result = EnrollmentSession.withDecryptionKeys { PgpDecryptor.decrypt(it, armored, emptyList()) }
            val ok = result as? DecryptResult.Ok ?: throw AssertionError("$field: $result")
            assertEquals(field, historicalPlaintext, String(ok.plaintext, Charsets.UTF_8))
        }
    }

    @Test
    fun theActiveMemberSignsAndIsWhatSelfEncryptionTargets() {
        hold()
        val ownKey = requireNotNull(EnrollmentSession.withSigner { it?.let { ring -> PgpEncryptor.ownPublicKey(ring) } })
        assertEquals(active, PgpFingerprint.compute(ownKey)!!.replace(" ", ""))

        val message = "signed by the active member".toByteArray()
        val encrypted = requireNotNull(EnrollmentSession.withSigner { PgpEncryptor.encrypt(message, listOf(ownKey), it) })
        val armored = (encrypted as EncryptResult.Ok).armored

        val opened = EnrollmentSession.withDecryptionKeys { PgpDecryptor.decrypt(it, armored, listOf(ownKey)) } as DecryptResult.Ok
        assertArrayEquals(message, opened.plaintext)
        val signature = opened.signature as RawSignature.Checked
        assertTrue("signed by the active key and verified against it", signature.verified)
        val activeSigningKeyId = requireNotNull(parsePgpKeyring(ringBytes, active)).active.ring.publicKey.keyID
        assertEquals(activeSigningKeyId, signature.keyId)
    }

    /** Legacy accessors see nothing, so a keyring can never reach the armor parser or the merge. */
    @Test
    fun aKeyringIsInvisibleToTheLegacyAccessors() {
        hold()
        assertTrue(EnrollmentSession.isHeld())
        assertNull(EnrollmentSession.withLegacyArmor { it.size })
        assertNull(EnrollmentSession.peekForTest())
        assertNotNull(EnrollmentSession.withKeyring { it.activeFingerprint })
    }

    @Test
    fun legacyArmorSeesNoKeyringAccessor() {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        assertNull(EnrollmentSession.withKeyring { it })
        assertNotNull(EnrollmentSession.withLegacyArmor { it.size })
        assertNotNull("legacy armor still signs with its first ring", EnrollmentSession.withSigner { it })
    }

    @Test
    fun clearWipesTheKeyringItOwned() {
        val ring = requireNotNull(parsePgpKeyring(ringBytes, active))
        EnrollmentSession.putKeyring(ring)
        EnrollmentSession.clear()
        assertFalse(EnrollmentSession.isHeld())
        assertTrue(ring.original.all { it == 0.toByte() })
        assertTrue(ring.members.all { m -> m.armor.all { it == 0.toByte() } })
    }

    @Test
    fun anOpenedRecordInstallsByItsDeclaredKindOnly() {
        assertTrue(installOpenedMaterial(VaultRecordKind.KEYRING, ringBytes))
        assertNotNull(EnrollmentSession.withKeyring { it })
        EnrollmentSession.clear()

        assertFalse("a keyring record that no longer validates installs nothing", installOpenedMaterial(VaultRecordKind.KEYRING, "{}".toByteArray()))
        assertFalse(EnrollmentSession.isHeld())

        assertTrue(installOpenedMaterial(VaultRecordKind.LEGACY_ARMOR, "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray()))
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----", EnrollmentSession.peekForTest())

        // Declared legacy but carrying JSON: it lands in the legacy holder, where the armor parser
        // refuses it, rather than being parsed as a ring.
        assertTrue(installOpenedMaterial(VaultRecordKind.LEGACY_ARMOR, ringBytes))
        assertNull(EnrollmentSession.withSigner { it })
        assertNull(EnrollmentSession.withKeyring { it })
    }
}
