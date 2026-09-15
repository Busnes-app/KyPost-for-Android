package org.kysecurity.mail.pgp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigInteger
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertFailsWith

class DeviceEnvelopeTest {

    private val allVersions = setOf(ENVELOPE_VERSION_LEGACY, ENVELOPE_VERSION_KEYRING)

    /** RFC 5869 Test Case 1 — an independent vector, so this confirms the HKDF agrees with the
     *  standard rather than merely round-tripping through itself. */
    @Test
    fun hkdf_matchesRfc5869TestCase1() {
        val okm = hkdfSha256(
            ikm = ByteArray(22) { 0x0b },
            salt = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
            info = byteArrayOf(
                0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(),
                0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte(),
            ),
            length = 42,
        )

        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.joinToString("") { "%02x".format(it) },
        )
    }

    // ---- The shared vectors: every intermediate pinned, both versions, no production sealer. ----

    /** The Go and TypeScript references check these same bytes; passing all of them here proves
     *  framing compatibility for both versions from one fixture, and that v2 did not move. */
    @Test
    fun sharedVectors_pinEcdhHkdfAadAndCiphertextForBothVersions() {
        val fixture = SharedFixtures.deviceEnvelope()
        val devicePrivate = scalar(fixture.string("devicePrivateKey"))
        val devicePublic = P256.g.multiply(devicePrivate).normalize().getEncoded(false)
        assertArrayEquals(b64(fixture.string("devicePublicKey")), devicePublic)
        val vectors = fixture["vectors"]!!.jsonArray.map { it.jsonObject }
        assertEquals(2, vectors.size)

        vectors.forEachIndexed { index, vector ->
            val fields = requireNotNull(parseDeviceEnvelope(vector["envelope"].toString(), allVersions))
            assertEquals(index + 2, fields.version)
            val ephemeralPublic = P256.g.multiply(scalar(fixture.string("ephemeralPrivateKey"))).normalize()
            assertArrayEquals(ephemeralPublic.getEncoded(false), fields.epk)

            val shared = P256.curve.decodePoint(fields.epk).multiply(devicePrivate).normalize().affineXCoord.encoded
            assertArrayEquals("ECDH differs", b64(vector.string("sharedSecret")), shared)
            val key = hkdfSha256(shared, devicePublic, envelopeDomain(fields.version).toByteArray(), 32)
            assertArrayEquals("HKDF differs", b64(vector.string("aesKey")), key)
            val aad = deviceEnvelopeAad(fields.version, vector.string("deviceId"), vector.string("fingerprint"))
            assertArrayEquals("AAD differs", b64(vector.string("aad")), aad)

            val opened = openDeviceEnvelope(shared, devicePublic, fields, aad)
            assertArrayEquals(vector.string("plaintext").toByteArray(Charsets.UTF_8), opened)
        }
    }

    /** The v3 device ID carries multibyte UTF-8 and a pipe: lengths are bytes, not characters,
     *  and the delimiter is the length prefix, not any character. */
    @Test
    fun sharedVectors_v3DeviceIdIsMultibyteAndCountedInBytes() {
        val vector = v3Vector()
        val deviceId = vector.string("deviceId")
        assertTrue(deviceId.contains('|') && deviceId.length < deviceId.toByteArray().size)
        val aad = deviceEnvelopeAad(ENVELOPE_VERSION_KEYRING, deviceId, vector.string("fingerprint"))
        val domain = envelopeDomain(ENVELOPE_VERSION_KEYRING).toByteArray()
        val idLength = ((aad[domain.size].toInt() and 0xFF) shl 8) or (aad[domain.size + 1].toInt() and 0xFF)
        assertEquals(deviceId.toByteArray(Charsets.UTF_8).size, idLength)
    }

    @Test
    fun sharedVectors_v3RejectsWrongDeviceFingerprintDomainSaltPointOrTag() {
        val fixture = SharedFixtures.deviceEnvelope()
        val vector = v3Vector()
        val devicePrivate = scalar(fixture.string("devicePrivateKey"))
        val devicePublic = P256.g.multiply(devicePrivate).normalize().getEncoded(false)
        val fields = requireNotNull(parseDeviceEnvelope(vector["envelope"].toString(), allVersions))
        val shared = P256.curve.decodePoint(fields.epk).multiply(devicePrivate).normalize().affineXCoord.encoded
        val deviceId = vector.string("deviceId")
        val fingerprint = vector.string("fingerprint")
        val good = deviceEnvelopeAad(ENVELOPE_VERSION_KEYRING, deviceId, fingerprint)
        assertNotNull(openDeviceEnvelope(shared, devicePublic, fields, good))

        assertNull("wrong device", openDeviceEnvelope(shared, devicePublic, fields, deviceEnvelopeAad(3, "dev-1", fingerprint)))
        assertNull("trimmed device", openDeviceEnvelope(shared, devicePublic, fields, deviceEnvelopeAad(3, "$deviceId ", fingerprint)))
        assertNull("wrong fingerprint", openDeviceEnvelope(shared, devicePublic, fields, deviceEnvelopeAad(3, deviceId, "0".repeat(40))))
        // The v2 domain over v3 bytes: the version travels with the fields, so this is the only
        // way to even attempt it, and it must fail.
        val asLegacy = DeviceEnvelopeFields(ENVELOPE_VERSION_LEGACY, fields.epk, fields.iv, fields.ct)
        assertNull("v2 domain", openDeviceEnvelope(shared, devicePublic, asLegacy, deviceEnvelopeAad(2, deviceId, fingerprint)))
        assertNull("wrong salt", openDeviceEnvelope(shared, fields.epk, fields, good))
        val otherShared = P256.g.multiply(devicePrivate).normalize().affineXCoord.encoded
        assertNull("wrong point", openDeviceEnvelope(otherShared, devicePublic, fields, good))
        val tampered = DeviceEnvelopeFields(3, fields.epk, fields.iv, fields.ct.copyOf().also { it[it.size - 1] = (it.last().toInt() xor 1).toByte() })
        assertNull("tampered tag", openDeviceEnvelope(shared, devicePublic, tampered, good))
        val tamperedBody = DeviceEnvelopeFields(3, fields.epk, fields.iv, fields.ct.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
        assertNull("tampered ciphertext", openDeviceEnvelope(shared, devicePublic, tamperedBody, good))
    }

    /** Live enrollment's policy: a v3 envelope is malformed there, never reopened under v2. */
    @Test
    fun aV3EnvelopeIsRejectedWhereOnlyLegacyIsAllowed() {
        val vector = v3Vector()
        assertNull(parseDeviceEnvelope(vector["envelope"].toString(), setOf(ENVELOPE_VERSION_LEGACY)))
        assertNotNull(parseDeviceEnvelope(vector["envelope"].toString(), setOf(ENVELOPE_VERSION_KEYRING)))
        assertNull(parseDeviceEnvelope(v2Vector()["envelope"].toString(), setOf(ENVELOPE_VERSION_KEYRING)))
    }

    // ---- v3 framing: refused before any base64 or key work. ----

    @Test
    fun v3_rejectsMalformedFraming() {
        val envelope = v3Vector()["envelope"]!!.jsonObject
        fun with(vararg edits: Pair<String, kotlinx.serialization.json.JsonElement>) =
            JsonObject(envelope.toMutableMap().apply { edits.forEach { (k, v) -> put(k, v) } }).toString()
        fun withField(key: String, value: String) = with(key to JsonPrimitive(value))
        val epk = envelope.string("epk")
        val ct = envelope.string("ct")

        assertNotNull(parseDeviceEnvelope(envelope.toString(), allVersions))
        assertNull("quoted version", parseDeviceEnvelope(withField("v", "3"), allVersions))
        assertNull("unknown version", parseDeviceEnvelope(with("v" to JsonPrimitive(4)), allVersions))
        assertNull("unknown alg", parseDeviceEnvelope(withField("alg", "ECDH-P256+HKDF-SHA256+A128GCM"), allVersions))
        assertNull("extra key", parseDeviceEnvelope(with("kid" to JsonPrimitive("x")), allVersions))
        assertNull("missing key", parseDeviceEnvelope(JsonObject(envelope - "iv").toString(), allVersions))
        assertNull("numeric field", parseDeviceEnvelope(with("iv" to JsonPrimitive(1)), allVersions))
        assertNull("unpadded base64", parseDeviceEnvelope(withField("epk", epk.trimEnd('=')), allVersions))
        assertNull("url-safe alphabet", parseDeviceEnvelope(withField("ct", ct.replace('+', '-').replace('/', '_')), allVersions))
        assertNull("non-canonical trailing bits", parseDeviceEnvelope(withField("epk", epk.dropLast(2) + "W="), allVersions))
        assertNull("trailing garbage", parseDeviceEnvelope(withField("epk", "$epk!"), allVersions))
        assertNull("64-byte point", parseDeviceEnvelope(withField("epk", b64(b64(epk).copyOf(64))), allVersions))
        assertNull("compressed point", parseDeviceEnvelope(withField("epk", b64(b64(epk).also { it[0] = 0x02 })), allVersions))
        assertNull("off-curve point", parseDeviceEnvelope(withField("epk", b64(b64(epk).also { it[64] = (it[64].toInt() xor 1).toByte() })), allVersions))
        assertNull("identity point", parseDeviceEnvelope(withField("epk", b64(ByteArray(65).also { it[0] = 0x04 })), allVersions))
        assertNull("8-byte iv", parseDeviceEnvelope(withField("iv", b64(ByteArray(8))), allVersions))
        assertNull("tag-only ciphertext", parseDeviceEnvelope(withField("ct", b64(ByteArray(16))), allVersions))
        assertNull("short ciphertext", parseDeviceEnvelope(withField("ct", b64(ByteArray(15))), allVersions))
    }

    /** The 128 KiB bound is on UTF-8 bytes of the serialized envelope, measured before decoding. */
    @Test
    fun v3_rejectsASerializedEnvelopeOver128KiB() {
        val json = v3Vector()["envelope"].toString()
        val padded = json.dropLast(1) + " ".repeat(128 * 1024 - json.length + 2) + "}"
        assertNull(parseDeviceEnvelope(padded, allVersions))
        val multibyte = json.dropLast(1) + "," + "\"" + "試".repeat(43 * 1024) + "\":1}"
        assertTrue(multibyte.length < 128 * 1024)
        assertNull(parseDeviceEnvelope(multibyte, allVersions))
    }

    @Test
    fun utf8LengthCountsBytesNotChars() {
        assertEquals(0L, utf8Length(""))
        assertEquals(5L, utf8Length("dev-1"))
        assertEquals(3L, utf8Length("試"))
        assertEquals(4L, utf8Length("📬"))
        assertEquals("device-試験|📬".toByteArray(Charsets.UTF_8).size.toLong(), utf8Length("device-試験|📬"))
    }

    @Test
    fun strictBase64RefusesEveryNonCanonicalSpelling() {
        assertArrayEquals(byteArrayOf(1, 2, 3), strictBase64("AQID"))
        assertArrayEquals(byteArrayOf(1, 2), strictBase64("AQI="))
        assertNull(strictBase64(""))
        assertNull(strictBase64("AQI"))
        assertNull(strictBase64("AQJ="))
        assertNull(strictBase64("AQI=="))
        assertNull(strictBase64("AQ ID"))
        assertNull(strictBase64("AQID\n"))
    }

    // ---- AAD ----

    /** The AAD is a three-implementation contract; its exact bytes stop an envelope minted for one
     *  device being replayed at another, and stop one surviving an identity rotation. */
    @Test
    fun aad_isTheExactContractBytes() {
        val aad = deviceEnrollmentAadFixture()

        val expected = "kypost-device-envelope/v2".toByteArray() +
            byteArrayOf(0, 5) + "dev-1".toByteArray() +
            byteArrayOf(0, 8) + "ABCD1234".toByteArray()
        assertArrayEquals(expected, aad)
    }

    /** Why the fields are length-prefixed: `info|deviceId|fingerprint` lets a boundary shift collide. */
    @Test
    fun aad_isUnambiguousAcrossAFieldBoundary() {
        val shifted = deviceEnvelopeAad(2, "dev", "BADC0FFEE0123456789ABCDEF")
        val plain = deviceEnvelopeAad(2, "devBADC0FFEE", "0123456789ABCDEF")

        assertFalse(
            "field boundaries must not be shiftable between deviceId and fingerprint",
            shifted.contentEquals(plain),
        )
    }

    /** [PgpFingerprint.compute] returns space-grouped hex; the browser strips whitespace for its AAD. */
    @Test
    fun aad_normalisesASpaceGroupedFingerprint() {
        assertArrayEquals(
            deviceEnvelopeAad(2, "dev-1", "164D5B834E7FE9272DC7293B6D78ABF3D9179534"),
            deviceEnvelopeAad(2, "dev-1", "164D 5B83 4E7F E927 2DC7 293B 6D78 ABF3 D917 9534"),
        )
        assertArrayEquals(
            deviceEnvelopeAad(3, "dev-1", "164D5B834E7FE9272DC7293B6D78ABF3D9179534"),
            deviceEnvelopeAad(3, "dev-1", "164d 5b83 4e7f e927 2dc7 293b 6d78 abf3 d917 9534"),
        )
    }

    @Test
    fun aad_lowercaseHexIsNormalisedToUppercase() {
        assertArrayEquals(
            deviceEnvelopeAad(2, "dev-1", "ABCD1234"),
            deviceEnvelopeAad(2, "dev-1", "abcd1234"),
        )
    }

    /** Fails loudly at the call site rather than silently producing an AAD that will never open. */
    @Test
    fun aad_rejectsANonHexFingerprint() {
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(2, "dev-1", "not-a-fingerprint") }
    }

    /** v3 binds the validated active key, which can only be 40 or 64 hex digits; v2 keeps its
     *  looser legacy shape. Neither accepts an empty device ID or an unknown version. */
    @Test
    fun aad_v3RequiresAFullFingerprintAndANonEmptyDeviceId() {
        assertNotNull(deviceEnvelopeAad(2, "dev-1", "ABCD1234"))
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(3, "dev-1", "ABCD1234") }
        assertNotNull(deviceEnvelopeAad(3, "dev-1", "A".repeat(40)))
        assertNotNull(deviceEnvelopeAad(3, "dev-1", "A".repeat(64)))
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(3, "dev-1", "A".repeat(63)) }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(3, "", "A".repeat(40)) }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(2, "", "ABCD1234") }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(1, "dev-1", "A".repeat(40)) }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(3, "x".repeat(65_536), "A".repeat(40)) }
    }

    // ---- Legacy parsing, unchanged. ----

    @Test
    fun parse_acceptsAWellFormedLegacyEnvelope() {
        val fields = parseDeviceEnvelope(envelopeJson(), setOf(ENVELOPE_VERSION_LEGACY))

        assertNotNull(fields)
        assertEquals(ENVELOPE_VERSION_LEGACY, fields!!.version)
        assertEquals(65, fields.epk.size)
        assertEquals(12, fields.iv.size)
        assertEquals(32, fields.ct.size)
        assertNotNull("the legacy sealers always quoted the version", parseDeviceEnvelope(envelopeJson(v = "\"2\""), setOf(2)))
    }

    @Test
    fun parse_rejectsTheSupersededV1Envelope() {
        assertNull(parseDeviceEnvelope(envelopeJson(v = "1"), allVersions))
    }

    @Test
    fun parse_rejectsAnUnsupportedAlg() {
        assertNull(parseDeviceEnvelope(envelopeJson(alg = "something-else"), allVersions))
    }

    @Test
    fun parse_rejectsGarbage() {
        assertNull(parseDeviceEnvelope("not json", allVersions))
    }

    /** A non-96-bit IV does not throw — GCMParameterSpec accepts any length and derives J0 by GHASH
     *  — so it silently changes the key schedule and desynchronises this client from the browser.
     *  This check is the only thing that catches it. */
    @Test
    fun parse_rejectsAWrongLengthIv() {
        assertNull(parseDeviceEnvelope(envelopeJson(iv = b64(ByteArray(8))), allVersions))
    }

    @Test
    fun parse_rejectsACiphertextShorterThanTheGcmTag() {
        assertNull(parseDeviceEnvelope(envelopeJson(ct = b64(ByteArray(16))), allVersions))
    }

    /** Matches the browser, which requires exactly 65 bytes with an 0x04 prefix. Without this the
     *  ECDH layer is the only thing between an attacker-supplied blob and the enrollment key. */
    @Test
    fun parse_rejectsAnEpkThatIsNotAnUncompressedPoint() {
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(65).also { it[0] = 0x02 })), allVersions))
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(64).also { it[0] = 0x04 })), allVersions))
        assertNull(parseDeviceEnvelope(envelopeJson(epk = b64(ByteArray(200).also { it[0] = 0x04 })), allVersions))
    }

    /** Larger than any legacy envelope the key cap allows, rejected before JSON work. */
    @Test
    fun parse_rejectsALegacyEnvelopeOverTheDerivedBound() {
        val json = envelopeJson()
        val padded = json.dropLast(1) + " ".repeat(org.kysecurity.mail.MemoryBudget.PGP_DEVICE_ENVELOPE_LEGACY_BYTES) + "}"
        assertNull(parseDeviceEnvelope(padded, allVersions))
    }

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun b64(text: String): ByteArray = Base64.getDecoder().decode(text)
    private fun scalar(text: String): BigInteger = BigInteger(1, b64(text))
    private fun JsonObject.string(key: String): String = this[key]!!.jsonPrimitive.content
    private fun v2Vector(): JsonObject = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray[0].jsonObject
    private fun v3Vector(): JsonObject = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray[1].jsonObject

    private fun envelopeJson(
        v: String = "2",
        alg: String = "ECDH-P256+HKDF-SHA256+A256GCM",
        epk: String = b64(ByteArray(65).also { it[0] = 0x04 }),
        iv: String = b64(ByteArray(12)),
        ct: String = b64(ByteArray(32)),
    ): String = """{"v":$v,"alg":"$alg","epk":"$epk","iv":"$iv","ct":"$ct"}"""

    /** Opening must succeed with the right AAD... */
    @Test
    fun open_returnsThePlaintext() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertArrayEquals(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray(),
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnrollmentAadFixture()),
        )
    }

    /** ...and fail closed with a wrong deviceId. Hostile or stale — never a retry. */
    @Test
    fun open_refusesAWrongDeviceId() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertNull(
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnvelopeAad(2, "other-device", "ABCD1234")),
        )
    }

    /** ...and with a wrong fingerprint, which is what stops an envelope outliving a rotation. */
    @Test
    fun open_refusesAWrongFingerprint() {
        val f = sealedFixture(aad = deviceEnrollmentAadFixture())
        assertNull(
            openDeviceEnvelope(FIXTURE_SECRET, FIXTURE_SALT, f, deviceEnvelopeAad(2, "dev-1", "FFFFFFFF")),
        )
    }

    private fun deviceEnrollmentAadFixture() = deviceEnvelopeAad(2, "dev-1", "ABCD1234")

    /** Seals with the same KDF the implementation derives, so the test exercises the real key
     *  schedule rather than a hand-picked key. */
    private fun sealedFixture(aad: ByteArray): DeviceEnvelopeFields {
        val key = hkdfSha256(FIXTURE_SECRET, FIXTURE_SALT, "kypost-device-envelope/v2".toByteArray(), 32)
        val iv = ByteArray(12) { it.toByte() }
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, iv))
        cipher.updateAAD(aad)
        val ct = cipher.doFinal("-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray())
        return DeviceEnvelopeFields(version = 2, epk = ByteArray(65), iv = iv, ct = ct)
    }

    private companion object {
        val FIXTURE_SECRET = ByteArray(32) { 0x11 }
        val FIXTURE_SALT = ByteArray(65) { 0x22 }
        val P256 = ECNamedCurveTable.getByName("secp256r1")
    }

    /** RFC 5869's ceiling, and the reason it is enforced rather than assumed: the block counter is
     *  written as ONE byte, so at 256 blocks it wraps to zero and that round reproduces round 1's
     *  output. A silent key collision is not a failure mode worth leaving to "nobody calls it with
     *  that length". */
    @Test
    fun hkdfRefusesLengthsPastTheOneByteCounter() {
        assertFailsWith<IllegalArgumentException> {
            hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32 + 1)
        }
        assertFailsWith<IllegalArgumentException> {
            hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 0)
        }
    }

    @Test
    fun hkdfStillExpandsUpToTheCeiling() {
        assertEquals(255 * 32, hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32).size)
    }
}

/** The fixtures copied from KyPost-Server; see `src/test/resources/kypost-server/PROVENANCE.md`. */
internal object SharedFixtures {
    fun bytes(name: String): ByteArray =
        requireNotNull(SharedFixtures::class.java.getResourceAsStream("/kypost-server/$name")) { name }.use { it.readBytes() }

    fun deviceEnvelope(): JsonObject = Json.parseToJsonElement(String(bytes("device-envelope-v3.json"), Charsets.UTF_8)).jsonObject
    fun keyring(): JsonObject = Json.parseToJsonElement(String(bytes("pgp-keyring-v1.json"), Charsets.UTF_8)).jsonObject
}
