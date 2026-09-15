package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * The restart claim for a keyring bundle, around the same real kernel crash as
 * `EnrollmentVaultCrashDurabilityTest` and driven by the same script. Phase one seals the shared
 * fixture ring as a KEYRING record; phase two, in a fresh process after boot, reopens it from
 * storage alone, decrypts historical mail with a retained member and signs with the active one.
 * The seal uses a fixed test-only AES key rather than the Keystore key, because opening the
 * Keystore key needs a biometric prompt; the record format and the reopen path are what is under
 * test, and the Keystore path is unchanged code.
 */
@RunWith(AndroidJUnit4::class)
class EnrollmentKeyringCrashDurabilityTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())
    private val testKey = SecretKeySpec(ByteArray(32) { 0x42 }, "AES")
    private val fixture = Json.parseToJsonElement(
        requireNotNull(javaClass.classLoader!!.getResourceAsStream("kypost-server/pgp-keyring-v1.json")).use { String(it.readBytes(), Charsets.UTF_8) },
    ).jsonObject
    private val ringBytes = fixture["ring"]!!.jsonObject.toString().toByteArray(Charsets.UTF_8)
    private val active = fixture["ring"]!!.jsonObject["activeFingerprint"]!!.jsonPrimitive.content

    @Before
    fun onlyUnderTheScript() {
        assumeTrue(
            "run through scripts/vault-crash-check.sh",
            InstrumentationRegistry.getArguments().getString("crashCheck") == "true",
        )
        EnrollmentSession.clear()
    }

    @After fun cleanup() { EnrollmentSession.clear() }

    @Test
    fun phase1SealsAKeyringRecord() {
        vault.destroy()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, testKey) }
        assertNotNull(parsePgpKeyring(ringBytes, active))
        assertEquals(SealOutcome.Sealed, commitSeal(vault, cipher, ringBytes, VaultRecordKind.KEYRING))
        assertEquals(VaultRecordKind.KEYRING, vault.stored()!!.kind)
    }

    @Test
    fun phase2ReopensDecryptsHistoryAndSignsAfterTheCrash() {
        val record = vault.stored() ?: throw AssertionError("the keyring record did not survive the crash")
        assertEquals(VaultRecordKind.KEYRING, record.kind)
        val plaintext = Cipher.getInstance("AES/GCM/NoPadding")
            .apply {
                init(Cipher.DECRYPT_MODE, testKey, GCMParameterSpec(128, record.iv))
                updateAAD(byteArrayOf(record.kind.recordVersion))
            }
            .doFinal(record.ciphertext)
        assertArrayEquals(ringBytes, plaintext)

        assertTrue(installOpenedMaterial(record.kind, plaintext))
        val expected = fixture["plaintext"]!!.jsonPrimitive.content
        for (field in listOf("ciphertext", "hiddenCiphertext")) {
            val armored = fixture[field]!!.jsonPrimitive.content
            val opened = EnrollmentSession.withDecryptionKeys { PgpDecryptor.decrypt(it, armored, emptyList()) } as DecryptResult.Ok
            assertEquals(field, expected, String(opened.plaintext, Charsets.UTF_8))
        }
        val ownKey = requireNotNull(EnrollmentSession.withSigner { it?.let { ring -> PgpEncryptor.ownPublicKey(ring) } })
        assertEquals(active, PgpFingerprint.compute(ownKey)!!.replace(" ", ""))
        val signed = EnrollmentSession.withSigner { PgpEncryptor.encrypt("after restart".toByteArray(), listOf(ownKey), it) }
        assertTrue(signed is EncryptResult.Ok)

        assertEquals(emptyList<String>(), vault.destroy())
    }
}
