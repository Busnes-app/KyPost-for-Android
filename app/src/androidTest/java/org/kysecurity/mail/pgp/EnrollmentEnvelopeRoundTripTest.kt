package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec
import java.security.interfaces.ECPublicKey
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** sealCipher is unreachable here: its key needs per-use auth from a BiometricPrompt. */
@RunWith(AndroidJUnit4::class)
class EnrollmentEnvelopeRoundTripTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    @Before fun clean() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }
    @After fun cleanup() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }

    /** Plays the browser's part: mint an ephemeral P-256 key, agree with the device's published
     *  point, derive with the device's point as the HKDF salt, and seal under the v2 AAD. */
    private fun sealAsBrowserWould(
        devicePoint: ByteArray,
        deviceId: String,
        fingerprint: String,
        plaintext: ByteArray,
    ): String {
        val ephemeral = KeyPairGenerator.getInstance("EC").apply {
            initialize(ECGenParameterSpec("secp256r1"))
        }.generateKeyPair()

        val devicePublic = java.security.KeyFactory.getInstance("EC").generatePublic(
            java.security.spec.ECPublicKeySpec(
                java.security.spec.ECPoint(
                    java.math.BigInteger(1, devicePoint.copyOfRange(1, 33)),
                    java.math.BigInteger(1, devicePoint.copyOfRange(33, 65)),
                ),
                (ephemeral.public as ECPublicKey).params,
            ),
        )
        val shared = KeyAgreement.getInstance("ECDH").run {
            init(ephemeral.private)
            doPhase(devicePublic, true)
            generateSecret()
        }
        // Salt is the DEVICE's point, not the ephemeral one. Getting this backwards is the
        // single easiest way to build a system where nothing ever opens.
        val key = hkdfSha256(
            ikm = shared,
            salt = devicePoint,
            info = "kypost-device-envelope/v2".toByteArray(Charsets.UTF_8),
            length = 32,
        )
        val iv = ByteArray(12).also { java.security.SecureRandom().nextBytes(it) }
        val ct = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
            updateAAD(deviceEnvelopeAad(ENVELOPE_VERSION_LEGACY, deviceId, fingerprint))
            doFinal(plaintext)
        }
        val w = (ephemeral.public as ECPublicKey).w
        val epk = sec1UncompressedPoint(w.affineX, w.affineY)
        val b64 = java.util.Base64.getEncoder()
        return """{"v":"2","alg":"ECDH-P256+HKDF-SHA256+A256GCM","epk":"${b64.encodeToString(epk)}",""" +
            """"iv":"${b64.encodeToString(iv)}","ct":"${b64.encodeToString(ct)}"}"""
    }

    @Test
    fun aBrowserSealedEnvelopeOpensAgainstTheKeystoreKey() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val devicePoint = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        assertEquals(65, devicePoint.size)

        val plaintext = "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray(Charsets.UTF_8)
        val envelope = sealAsBrowserWould(devicePoint, "dev-1", "164D 5B83 4E7F E927", plaintext)

        val fields = requireNotNull(parseDeviceEnvelope(envelope, setOf(ENVELOPE_VERSION_LEGACY)))
        val shared = requireNotNull(EnrollmentKeyStore.sharedSecret(fields.epk))
        val opened = openDeviceEnvelope(
            sharedSecret = shared,
            ownRawPublicKey = devicePoint,
            fields = fields,
            // Space-grouped on the way in, exactly as PgpFingerprint.compute emits it. If
            // deviceEnvelopeAad stopped normalising, this would fail here rather than in the field.
            aad = deviceEnvelopeAad(ENVELOPE_VERSION_LEGACY, "dev-1", "164D 5B83 4E7F E927"),
        )

        assertArrayEquals(plaintext, opened)
    }

    /** The AAD binding, on real hardware: an envelope minted for another device does not open,
     *  even though the ECDH itself succeeds. */
    @Test
    fun anEnvelopeSealedForAnotherDeviceDoesNotOpen() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val devicePoint = requireNotNull(EnrollmentKeyStore.rawPublicKey())
        val envelope = sealAsBrowserWould(devicePoint, "someone-else", "164D5B834E7FE927", ByteArray(64))

        val fields = requireNotNull(parseDeviceEnvelope(envelope, setOf(ENVELOPE_VERSION_LEGACY)))
        val shared = requireNotNull(EnrollmentKeyStore.sharedSecret(fields.epk))

        assertNull(
            openDeviceEnvelope(shared, devicePoint, fields, deviceEnvelopeAad(ENVELOPE_VERSION_LEGACY, "dev-1", "164D5B834E7FE927")),
        )
    }

    /** The agreement key's life is one ceremony. A second `newKeyPair()` must not reuse the first. */
    @Test
    fun aFreshCeremonyRotatesTheAgreementKey() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val first = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue(EnrollmentKeyStore.newKeyPair())
        val second = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue("a ceremony must not inherit the previous key", !first.contentEquals(second))
    }

    /** The vault half, end to end, minus the BiometricPrompt: seal with an authenticated cipher is
     *  not reachable here, but ensureKey/store/stored/destroy are. */
    @Test
    fun theVaultStoresAndDestroysWhatTheCeremonyWouldWrite() {
        assertTrue("no secure lock screen on this device — see the CI locksettings step", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 })

        assertNotNull(vault.stored())
        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))

        assertTrue(EnrollmentTeardown.destroy(ApplicationProvider.getApplicationContext()).isEmpty())

        // An instance held across teardown reports stale state; callers always build a fresh one.
        assertNull(EnrollmentVault(ApplicationProvider.getApplicationContext()).stored())
    }
}
