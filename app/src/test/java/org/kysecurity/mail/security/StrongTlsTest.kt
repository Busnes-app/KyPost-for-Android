package org.kysecurity.mail.security

import okhttp3.ConnectionSpec
import okhttp3.TlsVersion
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.pairingHttpClient
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.interfaces.ECPublicKey
import java.security.spec.ECFieldFp
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.EllipticCurve
import java.security.spec.RSAPublicKeySpec

/** Predicate and wiring only; `StrongTlsDeviceTest` proves real handshakes on Android. */
class StrongTlsTest {
    private fun rsa(bits: Int): PublicKey {
        val modulus = BigInteger.ONE.shiftLeft(bits - 1).add(BigInteger.valueOf(3))
        return KeyFactory.getInstance("RSA").generatePublic(RSAPublicKeySpec(modulus, BigInteger.valueOf(65537)))
    }

    @Test fun literalRsaBitsDecideTheFloor() {
        for (bits in listOf(1024, 2047)) assertFalse("$bits", StrongTls.meetsFloor(rsa(bits)))
        for (bits in listOf(2048, 4096)) assertTrue("$bits", StrongTls.meetsFloor(rsa(bits)))
    }

    @Test fun strongEcKeysPass() {
        for (curve in listOf("secp256r1", "secp384r1", "secp521r1")) {
            val key = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec(curve)) }.generateKeyPair().public
            assertTrue(curve, StrongTls.meetsFloor(key))
        }
    }

    @Test fun undersizedEcAndUnknownKeysFail() {
        val original = KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }
            .generateKeyPair().public as ECPublicKey
        val field = ECFieldFp(BigInteger.ONE.shiftLeft(224).subtract(BigInteger.valueOf(17)))
        val params = ECParameterSpec(EllipticCurve(field, BigInteger.ONE, BigInteger.ONE), original.params.generator, original.params.order, 1)
        assertFalse(StrongTls.meetsFloor(object : ECPublicKey by original { override fun getParams() = params }))
        assertFalse(StrongTls.meetsFloor(object : PublicKey {
            override fun getAlgorithm() = "unknown"
            override fun getFormat() = "X.509"
            override fun getEncoded() = byteArrayOf()
        }))
    }

    @Test(expected = CertificateException::class)
    fun anEmptyValidatedPathFailsClosed() = StrongTls.requireStrongChain(emptyList())

    @Test(expected = CertificateException::class)
    fun hostnameFreeVerificationIsRefused() =
        StrongTls.StrongTrustManager(StrongTls.platformTrustManager()).checkServerTrusted(emptyArray(), "RSA")

    /** Every client the app builds descends from this one, pinned or not. */
    @Test fun everyAppClientCarriesThePolicy() {
        for (client in listOf(
            pairingHttpClient(PinPosture.TofuWindow),
            pairingHttpClient(PinPosture.Pinned("relay.example", setOf("sha256/" + "A".repeat(43) + "=")), 15_000),
        )) {
            assertTrue(client.x509TrustManager is StrongTls.StrongTrustManager)
            assertEquals(listOf(ConnectionSpec.RESTRICTED_TLS), client.connectionSpecs)
        }
    }

    /** No TLS 1.0/1.1, CBC, 3DES, SHA-1 MAC or non-forward-secret RSA key exchange. */
    @Test fun restrictedSpecOffersOnlyModernSuites() {
        val spec = ConnectionSpec.RESTRICTED_TLS
        assertEquals(setOf(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2), spec.tlsVersions!!.toSet())
        for (suite in spec.cipherSuites!!.map { it.javaName }) {
            assertTrue(suite, suite.startsWith("TLS_AES_") || suite.startsWith("TLS_CHACHA20_") || suite.startsWith("TLS_ECDHE_"))
            assertTrue(suite, "GCM" in suite || "CHACHA20_POLY1305" in suite)
        }
    }
}
