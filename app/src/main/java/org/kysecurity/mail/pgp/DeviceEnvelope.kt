package org.kysecurity.mail.pgp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.asn1.x9.ECNamedCurveTable
import org.kysecurity.mail.MemoryBudget
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** HKDF info and AAD prefix, per version. Changing either strands every device on that version. */
private const val ENVELOPE_DOMAIN_PREFIX = "kypost-device-envelope/v"
private const val ENVELOPE_ALG = "ECDH-P256+HKDF-SHA256+A256GCM"
private const val GCM_TAG_BITS = 128
private const val TAG = "DeviceEnvelope"

/** One armored private key, sealed by the browser's legacy path. Live enrollment accepts only this. */
internal const val ENVELOPE_VERSION_LEGACY = 2

/** The complete `kypost-pgp-keyring-v1` ring. Framing is prepared here; nothing dispatches it yet. */
internal const val ENVELOPE_VERSION_KEYRING = 3

internal fun envelopeDomain(version: Int): String = "$ENVELOPE_DOMAIN_PREFIX$version"

/** HKDF-SHA256 (RFC 5869), extract-then-expand. Built from [Mac] rather than pulled in as a
 *  dependency: this app adds none for crypto. */
internal fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, length: Int): ByteArray {
    // RFC 5869's own ceiling. The counter is written as ONE byte, so past 255 blocks it wraps to
    // zero and round 256 reproduces round 1's output — a silent key collision rather than an error.
    require(length in 1..(255 * 32)) { "HKDF-SHA256 cannot expand to $length bytes" }
    val mac = Mac.getInstance("HmacSHA256")
    mac.init(SecretKeySpec(salt, "HmacSHA256"))
    val prk = mac.doFinal(ikm)

    val out = ByteArray(length)
    var previous = ByteArray(0)
    var written = 0
    var counter = 1
    while (written < length) {
        mac.init(SecretKeySpec(prk, "HmacSHA256"))
        mac.update(previous)
        mac.update(info)
        mac.update(counter.toByte())
        previous = mac.doFinal()
        val take = minOf(previous.size, length - written)
        previous.copyInto(out, written, 0, take)
        written += take
        counter++
    }
    return out
}

/** Not a `data class`: generated equals over [ByteArray] would be identity, not structural. The
 *  version is parsed once and travels with the fields, so the opener cannot be pointed at a
 *  different domain than the one the envelope declared. */
internal class DeviceEnvelopeFields(val version: Int, val epk: ByteArray, val iv: ByteArray, val ct: ByteArray)

/**
 * Null for anything malformed or unsupported; the caller re-runs the ceremony, never retries.
 * [allowedVersions] is the caller's dispatch policy: live enrollment passes only the legacy
 * version, so a v3 envelope is rejected there rather than opened under the wrong domain.
 */
internal fun parseDeviceEnvelope(json: String, allowedVersions: Set<Int>): DeviceEnvelopeFields? = runCatching {
    // A String's UTF-8 length is at least its char count, so this bounds the parse without
    // measuring; the exact v3 limit is applied below once the version is known.
    if (json.length > MemoryBudget.PGP_DEVICE_ENVELOPE_LEGACY_BYTES) return null
    val o = Json.parseToJsonElement(json).jsonObject
    val v = o["v"]?.jsonPrimitive ?: return null
    val version = when {
        // The legacy parser compared content only, so a quoted "2" has always opened; kept.
        v.content == ENVELOPE_VERSION_LEGACY.toString() -> ENVELOPE_VERSION_LEGACY
        !v.isString && v.content == ENVELOPE_VERSION_KEYRING.toString() -> ENVELOPE_VERSION_KEYRING
        else -> return null
    }
    if (version !in allowedVersions) return null
    if (o["alg"]?.jsonPrimitive?.content != ENVELOPE_ALG) return null
    if (version == ENVELOPE_VERSION_KEYRING) {
        if (o.keys != ENVELOPE_KEYS) return null
        if (utf8Length(json) > MemoryBudget.PGP_DEVICE_ENVELOPE_V3_BYTES) return null
    }
    val epk = strictBase64(o.getValue("epk").jsonPrimitive.let { if (it.isString) it.content else return null })
    val iv = strictBase64(o.getValue("iv").jsonPrimitive.let { if (it.isString) it.content else return null })
    val ct = strictBase64(o.getValue("ct").jsonPrimitive.let { if (it.isString) it.content else return null })
    // Match the browser, which requires exactly 65 bytes with an 0x04 prefix before it will import
    // the point. For the legacy version the Keystore agreement (`EnrollmentKeyStore.isOnCurve`)
    // is where an off-curve point dies; v3 is checked here as well, so the framing stands on its
    // own before any ECDH layer sees the point.
    if (epk == null || epk.size != 65 || epk[0] != 0x04.toByte()) return null
    if (version == ENVELOPE_VERSION_KEYRING && !isP256Point(epk)) return null
    if (iv == null || iv.size != 12) return null
    if (ct == null || ct.size <= GCM_TAG_BITS / 8) return null
    DeviceEnvelopeFields(version = version, epk = epk, iv = iv, ct = ct)
}.getOrNull()

private val ENVELOPE_KEYS = setOf("v", "alg", "epk", "iv", "ct")

/** Standard alphabet, padded, canonical: `java.util.Base64` alone accepts missing padding and
 *  non-zero trailing bits, both of which let two encodings name one ciphertext. */
internal fun strictBase64(text: String): ByteArray? {
    if (text.isEmpty() || text.length % 4 != 0) return null
    val bytes = runCatching { Base64.getDecoder().decode(text) }.getOrNull() ?: return null
    return bytes.takeIf { Base64.getEncoder().encodeToString(it) == text }
}

private fun isP256Point(encoded: ByteArray): Boolean = runCatching {
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
 *  The device ID goes in unchanged: no trimming, normalization or case folding. The fingerprint
 *  is uppercase hex without whitespace; v3 additionally requires a full 40- or 64-digit
 *  fingerprint, the only lengths a validated active key can have. */
internal fun deviceEnvelopeAad(version: Int, deviceId: String, pgpFingerprint: String): ByteArray {
    require(version == ENVELOPE_VERSION_LEGACY || version == ENVELOPE_VERSION_KEYRING) { "unsupported envelope version" }
    require(deviceId.isNotEmpty()) { "deviceId must not be empty" }
    val fingerprint = pgpFingerprint.uppercase().filterNot { it.isWhitespace() }
    require(fingerprint.isNotEmpty() && fingerprint.all { it in "0123456789ABCDEF" }) {
        "pgpFingerprint must be hex; got '${pgpFingerprint.take(24)}'"
    }
    if (version == ENVELOPE_VERSION_KEYRING) {
        require(fingerprint.length == 40 || fingerprint.length == 64) { "a v3 fingerprint is 40 or 64 hex digits" }
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

/** Null means hostile or stale, never a retry. [ownRawPublicKey] is the HKDF salt. The domain
 *  comes from the parsed version: a v3 envelope is never reopened as v2. */
internal fun openDeviceEnvelope(
    sharedSecret: ByteArray,
    ownRawPublicKey: ByteArray,
    fields: DeviceEnvelopeFields,
    aad: ByteArray,
): ByteArray? {
    var key: ByteArray? = null
    return try {
        key = hkdfSha256(sharedSecret, ownRawPublicKey, envelopeDomain(fields.version).toByteArray(Charsets.UTF_8), 32)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(GCM_TAG_BITS, fields.iv))
        cipher.updateAAD(aad)
        cipher.doFinal(fields.ct)
    } catch (e: javax.crypto.AEADBadTagException) {
        // The expected negative. Says nothing about this device being broken: the envelope was
        // minted for someone else, or under an identity the account no longer advertises.
        android.util.Log.w(TAG, "Device envelope failed authentication; it was not sealed for this device")
        null
    } catch (e: java.security.GeneralSecurityException) {
        android.util.Log.e(TAG, "Device envelope could not be opened", e)
        null
    } finally {
        // The derived key opens the account's PGP private key; do not leave it resident for GC.
        key?.fill(0)
    }
}
