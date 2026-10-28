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
import java.util.Base64
import kotlin.test.assertFailsWith

class DeviceEnvelopeTest {

    /** The only versions published, and so the only ones a current server seals for this device. */
    @Test
    fun onlyHpkeVersionsAreOpenable() {
        assertEquals(listOf(4, 5), OPENABLE_ENVELOPE_VERSIONS)
        assertTrue(RETIRED_ENVELOPE_VERSIONS.none { it in OPENABLE_ENVELOPE_VERSIONS })
    }

    // ---- Retired v2/v3: refused at framing, whatever their spelling. ----

    /** The server's v2 and v3 vectors are authentic and well-formed, and are not parsed. */
    @Test
    fun theSharedV2AndV3VectorsAreNotParsed() {
        val vectors = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray.map { it.jsonObject["envelope"]!!.jsonObject }
        assertEquals(listOf("2", "3"), vectors.map { it["v"]!!.jsonPrimitive.content })
        for (envelope in vectors) {
            assertNull(envelope.toString(), parseDeviceEnvelope(envelope.toString()))
            // The legacy parser also took a quoted "2".
            val quoted = JsonObject(envelope + ("v" to JsonPrimitive(envelope["v"]!!.jsonPrimitive.content)))
            assertNull(parseDeviceEnvelope(quoted.toString()))
        }
    }

    /** HPKE framing does not make v2/v3 openable: the version tag itself is refused. */
    @Test
    fun hpkeFramingLabelledAsARetiredVersionIsNotParsed() {
        assertNotNull(parseDeviceEnvelope(hpkeJson(v = "4")))
        assertNotNull(parseDeviceEnvelope(hpkeJson(v = "5")))
        for (v in listOf("2", "3", "1", "6", "\"4\"", "4.0", "true")) assertNull(v, parseDeviceEnvelope(hpkeJson(v = v)))
    }

    // ---- v4/v5 framing: refused before any key work. ----

    @Test
    fun hpke_rejectsMalformedFraming() {
        val envelope = Json.parseToJsonElement(hpkeJson()).jsonObject
        fun with(vararg edits: Pair<String, kotlinx.serialization.json.JsonElement>) =
            JsonObject(envelope.toMutableMap().apply { edits.forEach { (k, v) -> put(k, v) } }).toString()
        fun withField(key: String, value: String) = with(key to JsonPrimitive(value))
        val enc = envelope.string("enc")
        val ct = envelope.string("ct")

        val fields = requireNotNull(parseDeviceEnvelope(envelope.toString()))
        assertEquals(4, fields.version)
        assertArrayEquals(b64(enc), fields.epk)
        assertArrayEquals(b64(ct), fields.ct)
        assertNull("legacy alg", parseDeviceEnvelope(withField("alg", "ECDH-P256+HKDF-SHA256+A256GCM")))
        assertNull("extra key", parseDeviceEnvelope(with("iv" to JsonPrimitive(b64(ByteArray(12))))))
        assertNull("missing key", parseDeviceEnvelope(JsonObject(envelope - "ct").toString()))
        assertNull("legacy epk name", parseDeviceEnvelope(JsonObject(envelope - "enc" + ("epk" to JsonPrimitive(enc))).toString()))
        assertNull("numeric field", parseDeviceEnvelope(with("ct" to JsonPrimitive(1))))
        assertNull("unpadded base64", parseDeviceEnvelope(withField("enc", enc.trimEnd('='))))
        assertNull("url-safe alphabet", parseDeviceEnvelope(withField("ct", b64(ByteArray(32) { 0xFB.toByte() }).replace('+', '-').replace('/', '_'))))
        assertNull("non-canonical trailing bits", parseDeviceEnvelope(withField("enc", enc.dropLast(2) + "X=")))
        assertNull("trailing garbage", parseDeviceEnvelope(withField("enc", "$enc!")))
        assertNull("64-byte point", parseDeviceEnvelope(withField("enc", b64(b64(enc).copyOf(64)))))
        assertNull("compressed point", parseDeviceEnvelope(withField("enc", b64(b64(enc).also { it[0] = 0x02 }))))
        assertNull("off-curve point", parseDeviceEnvelope(withField("enc", b64(b64(enc).also { it[64] = (it[64].toInt() xor 1).toByte() }))))
        assertNull("identity point", parseDeviceEnvelope(withField("enc", b64(ByteArray(65).also { it[0] = 0x04 }))))
        assertNull("tag-only ciphertext", parseDeviceEnvelope(withField("ct", b64(ByteArray(16)))))
        assertNull("garbage", parseDeviceEnvelope("not json"))
    }

    /** v5 is bounded at 128 KiB of UTF-8, v4 at the derived one-key bound, both before decoding.
     *  Bytes, not chars: [utf8LengthCountsBytesNotChars]. */
    @Test
    fun hpke_rejectsAnEnvelopeOverItsVersionCap() {
        val v5 = hpkeJson(v = "5")
        val padded = v5.dropLast(1) + " ".repeat(128 * 1024 - v5.length + 2) + "}"
        assertNull(parseDeviceEnvelope(padded))

        // The one-key cap is the larger: a v4 past 128 KiB but within its own cap still parses.
        val v4 = hpkeJson(v = "4")
        val v4Cap = org.kysecurity.mail.MemoryBudget.PGP_DEVICE_ENVELOPE_LEGACY_BYTES
        assertTrue(v4Cap > 128 * 1024)
        assertNotNull(parseDeviceEnvelope(v4.dropLast(1) + " ".repeat(v4Cap - v4.length) + "}"))
        assertNull(parseDeviceEnvelope(v4.dropLast(1) + " ".repeat(v4Cap - v4.length + 1) + "}"))
        assertNull("v5 at that size", parseDeviceEnvelope(v5.dropLast(1) + " ".repeat(v4Cap - v5.length) + "}"))
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

    // ---- HPKE info (the binding) ----

    /** A three-implementation contract; its exact bytes stop an envelope minted for one device
     *  being replayed at another, and stop one surviving an identity rotation. */
    @Test
    fun binding_isTheExactContractBytes() {
        val expected = "kypost-device-envelope/v4".toByteArray() +
            byteArrayOf(0, 5) + "dev-1".toByteArray() +
            byteArrayOf(0, 8) + "ABCD1234".toByteArray()
        assertArrayEquals(expected, deviceEnvelopeAad(4, "dev-1", "ABCD1234"))
        assertArrayEquals(testBinding(5, "dev-1", "A".repeat(40)), deviceEnvelopeAad(5, "dev-1", "A".repeat(40)))
    }

    /** The shared vector's device ID carries multibyte UTF-8 and a pipe: lengths are bytes. */
    @Test
    fun binding_countsTheDeviceIdInBytes() {
        val vector = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray[1].jsonObject
        val deviceId = vector.string("deviceId")
        assertTrue(deviceId.contains('|') && deviceId.length < deviceId.toByteArray().size)
        val info = deviceEnvelopeAad(5, deviceId, vector.string("fingerprint"))
        val domain = envelopeDomain(5).toByteArray()
        val idLength = ((info[domain.size].toInt() and 0xFF) shl 8) or (info[domain.size + 1].toInt() and 0xFF)
        assertEquals(deviceId.toByteArray(Charsets.UTF_8).size, idLength)
    }

    /** Why the fields are length-prefixed: `info|deviceId|fingerprint` lets a boundary shift collide. */
    @Test
    fun binding_isUnambiguousAcrossAFieldBoundary() {
        assertFalse(deviceEnvelopeAad(4, "dev", "BADC0FFEE0123456789ABCDEF").contentEquals(deviceEnvelopeAad(4, "devBADC0FFEE", "0123456789ABCDEF")))
    }

    /** [PgpFingerprint.compute] returns space-grouped lowercase-or-upper hex; the browser binds bare uppercase. */
    @Test
    fun binding_normalisesTheFingerprint() {
        val bare = "164D5B834E7FE9272DC7293B6D78ABF3D9179534"
        for (version in OPENABLE_ENVELOPE_VERSIONS) {
            assertArrayEquals(deviceEnvelopeAad(version, "dev-1", bare), deviceEnvelopeAad(version, "dev-1", "164D 5B83 4E7F E927 2DC7 293B 6D78 ABF3 D917 9534"))
            assertArrayEquals(deviceEnvelopeAad(version, "dev-1", bare), deviceEnvelopeAad(version, "dev-1", bare.lowercase()))
        }
    }

    /** Fails loudly at the call site rather than silently producing a binding that will never open. */
    @Test
    fun binding_refusesRetiredVersionsAndMalformedInput() {
        for (version in RETIRED_ENVELOPE_VERSIONS + listOf(1, 6)) {
            assertFailsWith<IllegalArgumentException>("v$version") { deviceEnvelopeAad(version, "dev-1", "A".repeat(40)) }
        }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(4, "dev-1", "not-a-fingerprint") }
        assertNotNull(deviceEnvelopeAad(4, "dev-1", "ABCD1234"))
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(5, "dev-1", "ABCD1234") }
        assertNotNull(deviceEnvelopeAad(5, "dev-1", "A".repeat(64)))
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(5, "dev-1", "A".repeat(63)) }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(4, "", "ABCD1234") }
        assertFailsWith<IllegalArgumentException> { deviceEnvelopeAad(5, "x".repeat(65_536), "A".repeat(40)) }
    }

    private fun b64(bytes: ByteArray): String = Base64.getEncoder().encodeToString(bytes)
    private fun b64(text: String): ByteArray = Base64.getDecoder().decode(text)
    private fun JsonObject.string(key: String): String = this[key]!!.jsonPrimitive.content

    private fun hpkeJson(v: String = "4"): String {
        val enc = ECNamedCurveTable.getByName("secp256r1").g.getEncoded(false)
        return """{"v":$v,"alg":"HPKE-Base-P256-SHA256-A256GCM","enc":"${b64(enc)}","ct":"${b64(ByteArray(32) { 7 })}"}"""
    }
}

/** The fixtures copied from KyPost-Server; see `src/test/resources/kypost-server/PROVENANCE.md`. */
internal object SharedFixtures {
    fun bytes(name: String): ByteArray =
        requireNotNull(SharedFixtures::class.java.getResourceAsStream("/kypost-server/$name")) { name }.use { it.readBytes() }

    fun deviceEnvelope(): JsonObject = Json.parseToJsonElement(String(bytes("device-envelope-v3.json"), Charsets.UTF_8)).jsonObject
    fun keyring(): JsonObject = Json.parseToJsonElement(String(bytes("pgp-keyring-v1.json"), Charsets.UTF_8)).jsonObject
}
