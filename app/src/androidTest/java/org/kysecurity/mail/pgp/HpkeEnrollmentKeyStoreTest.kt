package org.kysecurity.mail.pgp

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.bouncycastle.crypto.hpke.HPKE
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore
import java.util.Base64

/** v4/v5 opened by the real Keystore agreement key through [hpkeOpenBase]; Bouncy Castle's HPKE
 *  plays the browser's sealing in software. The private key stays in the Keystore throughout. */
@RunWith(AndroidJUnit4::class)
class HpkeEnrollmentKeyStoreTest {

    private val deviceId = "dev-hpke-ü"
    private val fingerprint = "5F117951610CAF01500FA059CDE63F0EBEC934A2"
    private val plaintext = "sealed to the Keystore key".toByteArray()

    @Before fun clean() { EnrollmentKeyStore.deleteKeyPair() }
    @After fun cleanup() { EnrollmentKeyStore.deleteKeyPair() }

    private fun seal(devicePoint: ByteArray, version: Int): String {
        val hpke = HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)
        val info = deviceEnvelopeAad(version, deviceId, fingerprint)
        val (ct, enc) = hpke.seal(hpke.deserializePublicKey(devicePoint), info, ByteArray(0), plaintext, null, null, null)
        val b64 = Base64.getEncoder()
        return """{"v":$version,"alg":"HPKE-Base-P256-SHA256-A256GCM","enc":"${b64.encodeToString(enc)}","ct":"${b64.encodeToString(ct)}"}"""
    }

    /** The production open: framing, info from this device's own values, Keystore ECDH. */
    private fun open(envelope: String, version: Int = -1, deviceId: String = this.deviceId, fingerprint: String = this.fingerprint): ByteArray? {
        val fields = parseDeviceEnvelope(envelope) ?: return null
        val info = deviceEnvelopeAad(if (version == -1) fields.version else version, deviceId, fingerprint)
        return hpkeOpenBase(fields.epk, requireNotNull(EnrollmentKeyStore.rawPublicKey()), info, fields.ct, EnrollmentKeyStore::sharedSecret)
    }

    @Test
    fun keystoreKeyOpensV4AndV5AndStaysNonExportable() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val point = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        for (version in listOf(ENVELOPE_VERSION_HPKE, ENVELOPE_VERSION_HPKE_KEYRING)) {
            assertArrayEquals("v$version", plaintext, open(seal(point, version)))
        }
        val entry = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getEntry(EnrollmentKeyStore.ALIAS, null) as KeyStore.PrivateKeyEntry
        assertNull("the agreement key is never exportable", entry.privateKey.encoded)
    }

    @Test
    fun keystoreOpenRefusesAnyOtherBindingOrTamperedCiphertext() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val point = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        val v4 = seal(point, ENVELOPE_VERSION_HPKE)

        assertNull("relabeled as v5", open(v4.replace("\"v\":4", "\"v\":5")))
        assertNull("v5 info", open(v4, version = ENVELOPE_VERSION_HPKE_KEYRING))
        assertNull("other device", open(v4, deviceId = "dev-1"))
        assertNull("other fingerprint", open(v4, fingerprint = "A".repeat(40)))
        val fields = requireNotNull(parseDeviceEnvelope(v4))
        assertNull("no info", hpkeOpenBase(fields.epk, point, ByteArray(0), fields.ct, EnrollmentKeyStore::sharedSecret))
        val ct = Regex("\"ct\":\"([^\"]+)\"").find(v4)!!.groupValues[1]
        val tampered = Base64.getDecoder().decode(ct).also { it[it.size - 1] = (it[it.size - 1] + 1).toByte() }
        assertNull("tampered ct", open(v4.replace(ct, Base64.getEncoder().encodeToString(tampered))))

        assertTrue("a fresh key per ceremony", EnrollmentKeyStore.newKeyPair())
        assertNull("sealed to the previous key", open(v4))
    }
}
