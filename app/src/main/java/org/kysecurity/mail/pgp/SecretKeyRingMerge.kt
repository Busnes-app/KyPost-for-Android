package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSecretKey
import org.bouncycastle.openpgp.PGPMarker
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPadding
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.kysecurity.mail.MemoryBudget
import java.io.ByteArrayInputStream
import java.io.OutputStream
import java.util.Arrays

/** Adds every retired secret key to the newly enrolled collection, with current identities first. */
internal fun mergeSecretKeyRings(current: ByteArray, previous: CharArray): ByteArray? = runCatching {
    if (current.isEmpty() || current.size > MemoryBudget.PGP_SECRET_KEY_INPUT_BYTES) return null
    if (previous.isEmpty() ||
        previous.size > MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES ||
        previous.any { it.code > 0x7f }
    ) return null

    val currentRings = orderedSecretKeyRings(ByteArrayInputStream(current)) ?: return null
    val previousRings = previous.useArmoredStream(::orderedSecretKeyRings) ?: return null
    val result = mergeParsedSecretKeyRings(currentRings, previousRings) ?: return null
    serializeSecretKeyRings(result)
}.getOrNull()

internal fun mergeParsedSecretKeyRings(
    currentRings: List<PGPSecretKeyRing>,
    previousRings: List<PGPSecretKeyRing>,
): List<PGPSecretKeyRing>? {
    if (currentRings.isEmpty() || previousRings.isEmpty() ||
        currentRings.size > MemoryBudget.PGP_SECRET_KEY_RING_COUNT ||
        previousRings.size > MemoryBudget.PGP_SECRET_KEY_RING_COUNT
    ) return null
    val currentByPrimary = currentRings.associateBy { Fingerprint(it.publicKey.fingerprint) }.toMutableMap()
    val result = currentRings.toMutableList()
    previousRings.forEach { previousRing ->
        val primary = Fingerprint(previousRing.publicKey.fingerprint)
        val currentRing = currentByPrimary[primary]
        if (currentRing == null) {
            if (result.size == MemoryBudget.PGP_SECRET_KEY_RING_COUNT) return null
            result += previousRing
            currentByPrimary[primary] = previousRing
        } else {
            var merged: PGPSecretKeyRing = currentRing
            previousRing.secretKeys.asSequence().forEach { historical ->
                val currentSecret = merged.getSecretKey(historical.publicKey.fingerprint)
                if (currentSecret == null) {
                    merged = PGPSecretKeyRing.insertSecretKey(merged, historical)
                } else if (!historical.isPrivateKeyEmpty) {
                    // Same fingerprint, same private key: keep history without running an
                    // attacker-selected password KDF merely to choose its replacement.
                    val restored = PGPSecretKey.replacePublicKey(historical, currentSecret.publicKey)
                    merged = PGPSecretKeyRing.insertSecretKey(merged, restored)
                }
            }
            val historicalFingerprints = previousRing.secretKeys.asSequence()
                .map { Fingerprint(it.publicKey.fingerprint) }.toSet()
            val mergedFingerprints = merged.secretKeys.asSequence()
                .map { Fingerprint(it.publicKey.fingerprint) }.toSet()
            if (!mergedFingerprints.containsAll(historicalFingerprints)) return null
            if (previousRing.secretKeys.asSequence().any { historical ->
                    !historical.isPrivateKeyEmpty &&
                        merged.getSecretKey(historical.publicKey.fingerprint)?.isPrivateKeyEmpty != false
                }
            ) return null
            val index = result.indexOf(currentRing)
            result[index] = merged
            currentByPrimary[primary] = merged
        }
    }

    return result
}

internal fun serializeSecretKeyRings(rings: List<PGPSecretKeyRing>): ByteArray? = runCatching {
    BoundedSecretOutput(MemoryBudget.PGP_SECRET_KEY_OUTPUT_BYTES).use { sink ->
        ArmoredOutputStream(sink).use { armor -> rings.forEach { it.encode(armor) } }
        sink.takeBytes()
    }
}.getOrNull()

internal fun orderedSecretKeyRings(input: java.io.InputStream): List<PGPSecretKeyRing>? = runCatching {
    val encoded = BoundedSecretOutput(MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES).use { sink ->
        val scratch = ByteArray(MemoryBudget.PGP_SECRET_KEY_STREAM_BUFFER_BYTES)
        try {
            while (true) {
                val read = input.read(scratch)
                if (read < 0) break
                sink.write(scratch, 0, read)
            }
        } finally {
            Arrays.fill(scratch, 0)
        }
        sink.takeBytes()
    }
    try {
        if (!encoded.isSinglePrivateKeyArmor()) return null
        val source = ByteArrayInputStream(encoded)
        val factory = PGPObjectFactory(PGPUtil.getDecoderStream(source), BcKeyFingerprintCalculator())
        val rings = buildList {
            while (true) {
                when (val packet = factory.nextObject() ?: break) {
                    is PGPSecretKeyRing -> {
                        if (size == MemoryBudget.PGP_SECRET_KEY_RING_COUNT) return null
                        add(packet)
                    }
                    is PGPMarker, is PGPPadding -> Unit
                    else -> return null
                }
            }
        }
        val consumed = encoded.size - source.available()
        if (!encoded.isWhitespace(consumed, encoded.size)) return null
        rings.takeIf { it.isNotEmpty() }
    } finally {
        Arrays.fill(encoded, 0)
    }
}.getOrNull()

private fun ByteArray.isSinglePrivateKeyArmor(): Boolean {
    val begin = "-----BEGIN PGP PRIVATE KEY BLOCK-----".toByteArray(Charsets.US_ASCII)
    val end = "-----END PGP PRIVATE KEY BLOCK-----".toByteArray(Charsets.US_ASCII)
    val first = indexOf(begin)
    if (first < 0 || !isWhitespace(0, first)) return false
    if (indexOf(begin, first + begin.size) >= 0) return false
    val last = indexOf(end, first + begin.size)
    if (last < 0 || indexOf(end, last + end.size) >= 0) return false
    return isWhitespace(last + end.size, size)
}

private fun ByteArray.isWhitespace(start: Int, end: Int): Boolean {
    for (index in start until end) if (!this[index].isArmorWhitespace()) return false
    return true
}

private fun ByteArray.indexOf(needle: ByteArray, start: Int = 0): Int {
    for (index in start..size - needle.size) {
        if (needle.indices.all { this[index + it] == needle[it] }) return index
    }
    return -1
}

private fun Byte.isArmorWhitespace() =
    this == ' '.code.toByte() || this == '\t'.code.toByte() ||
        this == '\r'.code.toByte() || this == '\n'.code.toByte()

private class Fingerprint(private val bytes: ByteArray) {
    override fun equals(other: Any?) = other is Fingerprint && bytes.contentEquals(other.bytes)
    override fun hashCode() = bytes.contentHashCode()
}

/** Bounded armor sink whose abandoned or copied backing is always wiped. */
private class BoundedSecretOutput(private val limit: Int) : OutputStream() {
    private var bytes = ByteArray(minOf(4096, limit))
    private var size = 0
    private var taken = false

    override fun write(value: Int) {
        ensureCapacity(1)
        bytes[size++] = value.toByte()
    }

    override fun write(source: ByteArray, offset: Int, length: Int) {
        require(offset >= 0 && length >= 0 && offset <= source.size - length)
        ensureCapacity(length)
        source.copyInto(bytes, size, offset, offset + length)
        size += length
    }

    private fun ensureCapacity(extra: Int) {
        if (extra > limit - size) throw SecretKeyOutputTooLarge()
        if (size + extra <= bytes.size) return
        val replacement = bytes.copyOf(minOf(limit, maxOf(size + extra, bytes.size * 2)))
        Arrays.fill(bytes, 0)
        bytes = replacement
    }

    fun takeBytes(): ByteArray {
        check(!taken)
        taken = true
        if (size == bytes.size) return bytes
        return bytes.copyOf(size).also { Arrays.fill(bytes, 0) }
    }

    override fun close() {
        if (!taken) Arrays.fill(bytes, 0)
    }

    override fun toString() = "BoundedSecretOutput(redacted)"
}

private class SecretKeyOutputTooLarge : RuntimeException()
