package org.kysecurity.mail.pgp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.bouncycastle.crypto.hpke.HPKE
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import java.math.BigInteger
import javax.crypto.AEADBadTagException
import kotlin.test.assertFailsWith

/** RFC 9180 recipient adapter ([hpkeSetupBaseR], [hpkeOpenBase]) against the CFRG vector and an
 *  independent sender. The Keystore ECDH is replaced by [softwareDh]: the private scalar is test data. */
class HpkeRecipientTest {

    /**
     * The CFRG entry for mode 0 / kem_id 16 / kdf_id 1 / aead_id 2, from
     * https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/b1f7cb0cdeab6906c61b3d6574e8bdfdbe1cd3fb/test-vectors.json
     * (SHA-256 61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6), copied unmodified
     * via KyPost-Server `testdata/hpke-cfrg-p256-aes256.json`; `FixtureProvenanceTest` pins that copy.
     * RFC 9180 Appendix A.3.1 is the same KEM/KDF with AES-128-GCM, so it is not this suite.
     */
    private val vector = Json.parseToJsonElement(String(SharedFixtures.bytes("hpke-cfrg-p256-aes256.json"))).jsonObject["vector"]!!.jsonObject
    private fun v(name: String) = unhex(vector[name]!!.jsonPrimitive.content)

    @Test
    fun cfrgVector_selectsExactlyThisSuite() {
        assertEquals(listOf(0, 16, 1, 2), listOf("mode", "kem_id", "kdf_id", "aead_id").map { vector[it]!!.jsonPrimitive.content.toInt() })
        assertArrayEquals("pkRm is skRm's point", v("pkRm"), publicPoint(v("skRm")))
    }

    @Test
    fun cfrgVector_keyScheduleAndFirstOpenMatchByteForByte() {
        val context = requireNotNull(hpkeSetupBaseR(v("enc"), v("pkRm"), v("info"), softwareDh(v("skRm"))))

        assertArrayEquals("shared_secret", v("shared_secret"), context.sharedSecret)
        assertArrayEquals("key", v("key"), context.key)
        assertArrayEquals("base_nonce", v("base_nonce"), context.baseNonce)
        assertArrayEquals("exporter_secret", v("exporter_secret"), context.exporterSecret)
        val first = vector["encryptions"]!!.jsonArray[0].jsonObject
        fun e(name: String) = unhex(first[name]!!.jsonPrimitive.content)
        assertArrayEquals("encryptions[0].nonce is seq 0", e("nonce"), context.baseNonce)
        assertArrayEquals("encryptions[0].pt", e("pt"), context.openFirst(e("aad"), e("ct")))
    }

    /** Negative control for `info`: the vector's ciphertext does not open under any other info,
     *  including none. */
    @Test
    fun cfrgVector_refusesWithoutTheSameInfo() {
        val first = vector["encryptions"]!!.jsonArray[0].jsonObject
        fun e(name: String) = unhex(first[name]!!.jsonPrimitive.content)
        for (info in listOf(ByteArray(0), v("info").copyOf(v("info").size - 1))) {
            val context = requireNotNull(hpkeSetupBaseR(v("enc"), v("pkRm"), info, softwareDh(v("skRm"))))
            assertFailsWith<AEADBadTagException> { context.openFirst(e("aad"), e("ct")) }
        }
    }

    /** Bouncy Castle's HPKE as an independent sender, with KyPost's empty aad. */
    @Test
    fun opensWhatAnIndependentSenderSealed() {
        val hpke = HPKE(HPKE.mode_base, HPKE.kem_P256_SHA256, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)
        val skR = unhex("11".repeat(32))
        val pkR = publicPoint(skR)
        val info = deviceEnvelopeAad(ENVELOPE_VERSION_HPKE, "dev-1", FAKE_FINGERPRINT)
        val (ct, enc) = hpke.seal(hpke.deserializePublicKey(pkR), info, ByteArray(0), "sealed".toByteArray(), null, null, null)

        assertArrayEquals("sealed".toByteArray(), hpkeOpenBase(enc, pkR, info, ct, softwareDh(skR)))
        assertNull("other info", hpkeOpenBase(enc, pkR, deviceEnvelopeAad(ENVELOPE_VERSION_HPKE_KEYRING, "dev-1", FAKE_FINGERPRINT), ct, softwareDh(skR)))
        assertNull("tampered", hpkeOpenBase(enc, pkR, info, ct.copyOf().also { it[0] = (it[0] + 1).toByte() }, softwareDh(skR)))
        assertNull("other recipient point in kem_context", hpkeOpenBase(enc, publicPoint(unhex("22".repeat(32))), info, ct, softwareDh(skR)))
    }

    @Test
    fun anOffCurveEncNeverReachesTheKeystore() {
        var calls = 0
        val offCurve = ByteArray(65).also { it[0] = 0x04; it[64] = 1 }
        assertNull(hpkeSetupBaseR(offCurve, v("pkRm"), v("info")) { calls++; ByteArray(32) })
        assertNull(hpkeSetupBaseR(v("enc").copyOf(33), v("pkRm"), v("info")) { calls++; ByteArray(32) })
        assertEquals(0, calls)
    }

    @Test
    fun aRefusedOrMisSizedAgreementOpensNothing() {
        assertNull(hpkeSetupBaseR(v("enc"), v("pkRm"), v("info")) { null })
        assertNull(hpkeSetupBaseR(v("enc"), v("pkRm"), v("info")) { ByteArray(31) })
    }
}

/** RFC 9180 §7.1 DH for P-256: the x-coordinate of skR * pkE. Test stand-in for the Keystore. */
internal fun softwareDh(skR: ByteArray): (ByteArray) -> ByteArray? = { pkE ->
    ECNamedCurveTable.getByName("secp256r1").curve.decodePoint(pkE).multiply(BigInteger(1, skR)).normalize().affineXCoord.encoded
}

internal fun publicPoint(sk: ByteArray): ByteArray =
    ECNamedCurveTable.getByName("secp256r1").g.multiply(BigInteger(1, sk)).normalize().getEncoded(false)

internal fun unhex(hex: String): ByteArray = ByteArray(hex.length / 2) { hex.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
