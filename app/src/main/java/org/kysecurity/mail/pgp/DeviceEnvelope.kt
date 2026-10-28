package org.kysecurity.mail.pgp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.kysecurity.mail.MemoryBudget
import java.util.Base64

/** HPKE info prefix, per version. Changing it strands every device on that version. */
private const val ENVELOPE_DOMAIN_PREFIX = "kypost-device-envelope/v"
private const val HPKE_ENVELOPE_ALG = "HPKE-Base-P256-SHA256-A256GCM"
private const val GCM_TAG_BYTES = 16

/** Retired custom formats (ECDH + HKDF + AES-GCM, not a published construction): one armored key
 *  and the complete ring. Never opened; only named so a delivery of one gets its own refusal. */
internal val RETIRED_ENVELOPE_VERSIONS = setOf(2, 3)

/** The acknowledgement version of a keyring record stored before v5 existed (`EnrollmentVault`). */
internal const val ENVELOPE_VERSION_KEYRING = 3

/** One armored key (v4) and the complete `kypost-pgp-keyring-v1` ring (v5), sealed with RFC 9180
 *  HPKE (`HpkeRecipient.kt`); the binding is HPKE info. */
internal const val ENVELOPE_VERSION_HPKE = 4
internal const val ENVELOPE_VERSION_HPKE_KEYRING = 5

/** What this build opens, advertised on publish. */
internal val OPENABLE_ENVELOPE_VERSIONS = listOf(ENVELOPE_VERSION_HPKE, ENVELOPE_VERSION_HPKE_KEYRING)

internal fun isKeyringVersion(version: Int): Boolean = version == ENVELOPE_VERSION_HPKE_KEYRING

private fun envelopeCap(version: Int): Int =
    if (isKeyringVersion(version)) MemoryBudget.PGP_DEVICE_ENVELOPE_V3_BYTES else MemoryBudget.PGP_DEVICE_ENVELOPE_LEGACY_BYTES

internal fun envelopeDomain(version: Int): String = "$ENVELOPE_DOMAIN_PREFIX$version"

/** Not a `data class`: generated equals over [ByteArray] would be identity, not structural. The
 *  version is parsed once and travels with the fields, so the opener cannot be pointed at a
 *  different binding than the one the envelope declared. [epk] is HPKE `enc`. */
internal class DeviceEnvelopeFields(val version: Int, val epk: ByteArray, val ct: ByteArray)

private val HPKE_ENVELOPE_KEYS = setOf("v", "alg", "enc", "ct")

/**
 * v4/v5 framing, as strict as the server's `ParseDeviceEnvelopeVersion`: exactly
 * `{v, alg, enc, ct}`, numeric `v`, canonical base64, `enc` a P-256 point, a ciphertext longer
 * than its tag. Null for anything else, v2/v3 included; the caller re-runs the ceremony, never retries.
 */
internal fun parseDeviceEnvelope(json: String): DeviceEnvelopeFields? = runCatching {
    // A String's UTF-8 length is at least its char count, so this bounds the parse without
    // measuring; the exact per-version cap is applied once the version is known.
    if (json.length > OPENABLE_ENVELOPE_VERSIONS.maxOf(::envelopeCap)) return null
    val o = Json.parseToJsonElement(json).jsonObject
    val v = o["v"]?.jsonPrimitive ?: return null
    // Exact token match: no quoted "4", no 4.0 or 04.
    if (v.isString) return null
    val version = OPENABLE_ENVELOPE_VERSIONS.firstOrNull { it.toString() == v.content } ?: return null
    if (o.keys != HPKE_ENVELOPE_KEYS || o.getValue("alg").jsonPrimitive.content != HPKE_ENVELOPE_ALG) return null
    if (utf8Length(json) > envelopeCap(version)) return null
    val enc = o.getValue("enc").jsonPrimitive.takeIf { it.isString }?.let { strictBase64(it.content) }
    val ct = o.getValue("ct").jsonPrimitive.takeIf { it.isString }?.let { strictBase64(it.content) }
    if (enc == null || enc.size != 65 || enc[0] != 0x04.toByte() || !isP256Point(enc)) return null
    if (ct == null || ct.size <= GCM_TAG_BYTES) return null
    DeviceEnvelopeFields(version = version, epk = enc, ct = ct)
}.getOrNull()

/** Standard alphabet, padded, canonical: `java.util.Base64` alone accepts missing padding and
 *  non-zero trailing bits, both of which let two encodings name one ciphertext. */
internal fun strictBase64(text: String): ByteArray? {
    if (text.isEmpty() || text.length % 4 != 0) return null
    val bytes = runCatching { Base64.getDecoder().decode(text) }.getOrNull() ?: return null
    return bytes.takeIf { Base64.getEncoder().encodeToString(it) == text }
}

internal fun isP256Point(encoded: ByteArray): Boolean = runCatching {
    val point = ECNamedCurveTable.getByName("secp256r1").curve.decodePoint(encoded)
    !point.isInfinity && point.isValid
}.getOrDefault(false)

/** UTF-8 byte length without encoding: the bound has to hold before any copy is made. */
internal fun utf8Length(text: String): Long {
    var bytes = 0L
    var i = 0
    while (i < text.length) {
        val cp = text.codePointAt(i)
        bytes += when {
            cp < 0x80 -> 1
            cp < 0x800 -> 2
            cp < 0x10000 -> 3
            else -> 4
        }
        i += Character.charCount(cp)
    }
    return bytes
}

/** `domain || uint16BE(len(deviceId)) || deviceId || uint16BE(len(fingerprint)) || fingerprint`
 *
 *  The HPKE info. The device ID goes in unchanged: no trimming, normalization or case folding.
 *  The fingerprint is uppercase hex without whitespace; v5 additionally requires a full 40- or
 *  64-digit fingerprint, the only lengths a validated active key can have. */
internal fun deviceEnvelopeAad(version: Int, deviceId: String, pgpFingerprint: String): ByteArray {
    require(version in OPENABLE_ENVELOPE_VERSIONS) { "unsupported envelope version" }
    require(deviceId.isNotEmpty()) { "deviceId must not be empty" }
    val fingerprint = pgpFingerprint.uppercase().filterNot { it.isWhitespace() }
    require(fingerprint.isNotEmpty() && fingerprint.all { it in "0123456789ABCDEF" }) {
        "pgpFingerprint must be hex; got '${pgpFingerprint.take(24)}'"
    }
    if (isKeyringVersion(version)) {
        require(fingerprint.length == 40 || fingerprint.length == 64) { "a ring fingerprint is 40 or 64 hex digits" }
    }
    val info = envelopeDomain(version).toByteArray(Charsets.UTF_8)
    val id = deviceId.toByteArray(Charsets.UTF_8)
    val fp = fingerprint.toByteArray(Charsets.UTF_8)
    require(id.size <= 0xFFFF && fp.size <= 0xFFFF) { "AAD field too long to length-prefix" }
    return ByteBuffer.allocate(info.size + 2 + id.size + 2 + fp.size)
        .order(ByteOrder.BIG_ENDIAN)
        .put(info)
        .putShort(id.size.toShort())
        .put(id)
        .putShort(fp.size.toShort())
        .put(fp)
        .array()
}
