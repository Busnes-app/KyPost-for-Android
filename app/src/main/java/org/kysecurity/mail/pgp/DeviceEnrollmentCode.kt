package org.kysecurity.mail.pgp

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest

/** Crockford base32. Excludes I, L, O and U, so the user cannot mistype a code by confusing them. */
private const val CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

/** 14 chars x 5 bits = the first 70 bits of the digest. The search is offline; 50 bits was weak. */
private const val CODE_LENGTH = 14

/** SAS from this device's own keystore key (never server-supplied); deviceId hashed as-is. */
internal fun deviceEnrollmentCode(rawPublicKey: ByteArray, deviceId: String, bucket: Long): String {
    val id = deviceId.toByteArray(Charsets.UTF_8)
    require(rawPublicKey.size == 65 || rawPublicKey.size == XWING_PUBLIC_KEY_BYTES) { "unsupported enrollment key" }
    require(id.isNotEmpty() && id.size <= 0xFFFF && bucket >= 0) { "invalid SAS context" }
    val prefix = if (rawPublicKey.size == XWING_PUBLIC_KEY_BYTES) {
        "kypost-device-sas/v2".toByteArray(Charsets.UTF_8) + byteArrayOf(0x04, 0xC0.toByte())
    } else ByteArray(0)
    val preimage = ByteBuffer.allocate(prefix.size + rawPublicKey.size + 2 + id.size + 8)
        .order(ByteOrder.BIG_ENDIAN)
        .put(prefix)
        .put(rawPublicKey)
        .putShort(id.size.toShort())
        .put(id)
        .putLong(bucket)
        .array()

    val digest = MessageDigest.getInstance("SHA-256").digest(preimage)

    return buildString(CODE_LENGTH) {
        for (charIndex in 0 until CODE_LENGTH) {
            var value = 0
            for (offset in 0 until 5) {
                val bit = charIndex * 5 + offset
                value = (value shl 1) or ((digest[bit / 8].toInt() shr (7 - bit % 8)) and 1)
            }
            append(CROCKFORD[value])
        }
    }
}
