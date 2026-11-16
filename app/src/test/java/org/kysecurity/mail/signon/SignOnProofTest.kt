package org.kysecurity.mail.signon

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/** Golden vector from the owner-approved signon-binding spec (verified there with Go and openssl). */
class SignOnProofTest {
    private val spki = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYP7UuiVanTHJYet0xjVtaMBJuJI7Yfps5mliLmDyn7Z5A/4QCLi8maQa6elWKLxk8vGyDC1+n1F3o8KU1EYimQ=="
    private val idToken = "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ1c2VyLTEifQ.c2ln"
    private val origin = "https://relay.example.com"
    private val signature = "MEUCIAgEZ1PL1ngMWZe1DGinEVwy9mdQ12EGpwIQYjvApRVMAiEAg9zmYUWgIuQcNLh54gXJ+RVtc+vJZ3iy+N8jny2Ud0I="
    private val goldenKey: PublicKey =
        KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(Base64.getDecoder().decode(spki)))

    private fun verifies(key: PublicKey, message: ByteArray, sig: String) =
        Signature.getInstance("SHA256withECDSA").run {
            initVerify(key)
            update(message)
            verify(Base64.getDecoder().decode(sig))
        }

    @Test
    fun golden_thumbMessageAndSignature() {
        assertEquals("Wnp4zKSg9CDZvGK7Zpw8J1njn3I9OuENy-DwgVoH7NQ", SignOnProof.thumb(goldenKey))
        assertEquals(spki, SignOnProof.proofKey(goldenKey))
        val message = SignOnProof.message(origin, idToken)
        assertArrayEquals(
            "kypost-signon-pop/1\nhttps://relay.example.com\njJWmig6MLGIOyfYGNDGuWH3dGkbnpSqvek1tQ8PUgg8".toByteArray(Charsets.UTF_8),
            message,
        )
        assertTrue(verifies(goldenKey, message, signature))
        assertFalse(verifies(goldenKey, SignOnProof.message("https://evil.example.com", idToken), signature))
    }

    @Test
    fun freshKey_roundTrips() {
        val keys = SignOnProof.newKeyPair()
        assertTrue(Regex("^[A-Za-z0-9_-]{43}$").matches(SignOnProof.thumb(keys.public)))
        // Same 26-byte SPKI header as the golden key: id-ecPublicKey, prime256v1, uncompressed point.
        assertArrayEquals(goldenKey.encoded.copyOf(26), keys.public.encoded.copyOf(26))
        assertEquals(91, keys.public.encoded.size)
        val proof = SignOnProof.sign(keys, origin, idToken)
        assertTrue(verifies(keys.public, SignOnProof.message(origin, idToken), proof))
        assertFalse(verifies(keys.public, SignOnProof.message(origin, "$idToken.x"), proof))
        assertFalse(SignOnProof.thumb(keys.public) == SignOnProof.thumb(SignOnProof.newKeyPair().public))
    }
}
