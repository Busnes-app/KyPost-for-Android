package org.kysecurity.mail.pgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

@RunWith(AndroidJUnit4::class)
class EnrollmentVaultTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val vault = EnrollmentVault(context)
    private val recordFile = File(context.filesDir, EnrollmentVault.RECORD_FILE)
    private val pendingFile = File(context.filesDir, "${EnrollmentVault.RECORD_FILE}.new")
    private val legacyFile = File(File(context.dataDir, "shared_prefs"), "${EnrollmentVault.PREFS_FILE}.xml")

    // Block body, not an expression body: destroy() returns the steps it could not
    // complete, and JUnit requires @Before/@After to return void.
    @Before fun clean() { pendingFile.delete(); vault.destroy() }
    @After fun cleanup() { pendingFile.delete(); vault.destroy() }

    /** The property the whole re-seal buys. If this key could be used without the device lock
     *  screen, an extracted device image would open the envelope. */
    @Test
    fun theKeyRequiresUserAuthentication() {
        assertTrue(vault.ensureKey())

        assertTrue("key must require user authentication", vaultKeyInfo().isUserAuthenticationRequired)
    }

    @Test
    fun storesAndReadsBackTheBlob() {
        vault.ensureKey()
        assertFalse(vault.hasBlob())

        assertTrue(vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 }))

        assertTrue(vault.hasBlob())
        val (iv, ct) = vault.stored()!!
        assertNotNull(iv)
        assertTrue(ct.size == 40)
        assertFalse("a replacement must not leave its pending copy", pendingFile.exists())
    }

    @Test
    fun destroyRemovesBothTheKeyAndTheBlob() {
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(40))

        assertEquals(emptyList<String>(), vault.destroy())

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse(vault.hasBlob())
        assertFalse(recordFile.exists())
        assertNull(vault.stored())
    }

    @Test
    fun aReplacementSurvivesAFreshInstance() {
        vault.ensureKey()
        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })

        assertTrue(vault.store(ByteArray(12) { 3 }, ByteArray(48) { 4 }))

        val (iv, ct) = EnrollmentVault(context).stored()!!
        assertArrayEquals(ByteArray(12) { 3 }, iv)
        assertArrayEquals(ByteArray(48) { 4 }, ct)
    }

    /** The write is refused before the rename, so the record on disk is still the previous one and
     *  the key that opens it still matches its spec. */
    @Test
    fun aFailedReplacementLeavesThePreviousRecordAndTheKey() {
        assertTrue(vault.ensureKey())
        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })
        assertTrue("fault injection: the pending path is a directory", pendingFile.mkdir())

        assertFalse(vault.store(ByteArray(12) { 3 }, ByteArray(48) { 4 }))

        val (iv, ct) = EnrollmentVault(context).stored()!!
        assertArrayEquals(ByteArray(12) { 1 }, iv)
        assertArrayEquals(ByteArray(40) { 2 }, ct)
        assertTrue("the key must still be the one that sealed the record", vault.ensureKey())
        assertTrue(vaultKeyInfo().isUserAuthenticationRequired)
    }

    @Test
    fun aLegacyPreferenceRecordIsReadInPlaceAndRetiredOnlyByAReplacement() {
        vault.ensureKey()
        writeLegacy(ByteArray(12) { 5 }, ByteArray(48) { 6 })

        assertTrue(vault.hasBlob())
        assertArrayEquals(ByteArray(48) { 6 }, vault.stored()!!.second)
        assertFalse("reading must not migrate", recordFile.exists())
        assertTrue(legacyFile.exists())

        assertTrue(vault.store(ByteArray(12) { 7 }, ByteArray(48) { 8 }))

        assertArrayEquals(ByteArray(48) { 8 }, EnrollmentVault(context).stored()!!.second)
        assertFalse("the legacy copy is retired once the file is durable", legacyFile.exists())
    }

    /** Regenerating here would strand the record under a key nothing can use. Only "Remove from
     *  this device" may discard it. */
    @Test
    fun ensureKeyDoesNotRegenerateOverAStoredRecordWithAnUnusableKey() {
        generateKeyWithoutUserAuthentication()
        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })

        assertFalse(vault.ensureKey())

        assertFalse("the mismatched key was replaced", vaultKeyInfo().isUserAuthenticationRequired)
        assertArrayEquals(ByteArray(40) { 2 }, vault.stored()!!.second)
        assertTrue(vault.hasBlob())

        vault.destroy()
        assertTrue("with nothing sealed, a fresh key is fine", vault.ensureKey())
        assertTrue(vaultKeyInfo().isUserAuthenticationRequired)
    }

    /** One negative `containsAlias` is a transient Keystore fault until proven otherwise. Clearing on
     *  it would delete the only copy of the merged secret-key collection. */
    @Test
    fun aTransientAbsentAliasDoesNotClearTheRecord() {
        assertTrue(vault.ensureKey())
        vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 })
        val lying = lyingKeyStore(lies = 1)
        val flaky = EnrollmentVault(context) { lying }

        assertFalse("an uncorroborated absence must not mint a key", flaky.ensureKey())

        assertTrue(recordFile.exists())
        val (iv, ct) = EnrollmentVault(context).stored()!!
        assertArrayEquals(ByteArray(12) { 1 }, iv)
        assertArrayEquals(ByteArray(40) { 2 }, ct)
        assertTrue("the real key is untouched", vault.ensureKey())
    }

    @Test
    fun malformedRecordsFailClosed() {
        vault.ensureKey()
        val tooShort = ByteArray(1 + 12 + 15) { 1 }
        val wrongVersion = ByteArray(1 + 12 + 16) { 1 }.also { it[0] = 2 }
        val tooLong = ByteArray(1 + 12 + 384 * 1024 + 17) { 1 }
        for (bytes in listOf(tooShort, wrongVersion, tooLong)) {
            recordFile.writeBytes(bytes)
            assertTrue("a ${bytes.size}-byte record must fail", runCatching { vault.stored() }.isFailure)
            assertTrue(vault.hasBlob())
        }
        assertFalse(vault.store(ByteArray(11), ByteArray(48)))
        assertFalse(vault.store(ByteArray(12), ByteArray(15)))
        assertEquals(emptyList<String>(), vault.destroy())
        assertNull(vault.stored())
    }

    /** The sealer's write step, with a throwaway cipher standing in for the authenticated one. */
    @Test
    fun commitSealReportsSealedOnlyForADurableRecord() {
        vault.ensureKey()
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        val plaintext = ByteArray(64) { 3 }

        assertEquals(SealOutcome.Sealed, commitSeal(vault, encryptor(key), plaintext))
        val (iv, ct) = EnrollmentVault(context).stored()!!
        val opened = Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, iv)) }
            .doFinal(ct)
        assertArrayEquals(plaintext, opened)

        assertTrue(pendingFile.mkdir())
        assertTrue(commitSeal(vault, encryptor(key), ByteArray(64) { 4 }) is SealOutcome.Failed)
        assertArrayEquals(ct, EnrollmentVault(context).stored()!!.second)
    }

    private fun encryptor(key: SecretKey): Cipher =
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }

    private fun vaultKeyInfo(): KeyInfo {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        val key = ks.getKey(EnrollmentVault.ALIAS, null) as SecretKey
        return SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
    }

    private fun generateKeyWithoutUserAuthentication() {
        val spec = KeyGenParameterSpec.Builder(
            EnrollmentVault.ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
            .apply { init(spec) }
            .generateKey()
    }

    private fun writeLegacy(iv: ByteArray, ct: ByteArray) {
        val field = EnrollmentVault::class.java.getDeclaredField("prefs\$delegate").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val prefs = (field.get(vault) as Lazy<SharedPreferences>).value
        assertTrue(
            prefs.edit()
                .putString("envelope_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString("envelope_ct", Base64.encodeToString(ct, Base64.NO_WRAP))
                .commit(),
        )
    }
}
