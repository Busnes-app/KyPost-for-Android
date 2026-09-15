package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignatureList
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import java.io.ByteArrayOutputStream
import java.io.InputStream

internal const val MAX_DECRYPTED_PLAINTEXT_BYTES = org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_BYTES

/** How many nested OpenPGP compressed-data packets [PgpDecryptor.readLiteral] will unwrap. Real
 *  messages use one; anything past a handful is a decompression bomb, not a mail. */
internal const val MAX_COMPRESSION_DEPTH = 4

/** Three states, not two booleans: "signed by a key we were not given" is not "failed to verify". */
internal sealed class RawSignature {
    object Absent : RawSignature()

    /** Signed, but no key with this id was among the ones offered — so nothing was checked. Never
     *  an accusation; see [PgpSignatureState.SIGNER_UNKNOWN]. */
    data class NoSuchKey(val keyId: Long) : RawSignature()

    data class Checked(val keyId: Long, val verified: Boolean) : RawSignature()

    val present: Boolean get() = this !is Absent

    /** False for [NoSuchKey]: a signature nothing checked is not a good signature. */
    val valid: Boolean get() = (this as? Checked)?.verified == true

    val signerKeyId: Long get() = when (this) {
        is Absent -> 0L
        is NoSuchKey -> keyId
        is Checked -> keyId
    }
}

internal sealed class DecryptResult {
    data class Ok(val plaintext: ByteArray, val signature: RawSignature) : DecryptResult() {
        /** Redacted: the plaintext is a decrypted message. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Ok(redacted)"

        // A data class with a ByteArray property has identity equals; nothing compares these.
        override fun equals(other: Any?) = this === other
        override fun hashCode() = System.identityHashCode(this)
    }

    data class Failed(val message: String) : DecryptResult()
}

/** Bc* operators, never Jce*: Android's stripped "BC" JCE provider makes the Jce path differ. */
internal object PgpDecryptor {

    fun decrypt(
        /** The enrolled key as a [CharArray], never a `String`: [EnrollmentSession] holds it in a
         *  wipeable array precisely so no caller has to mint an immortal copy to reach this. */
        armoredPrivateKey: CharArray,
        armoredMessage: String,
        /** From the address book, never the key inside the message; empty means unverifiable. */
        signerPublicKeys: List<String>,
    ): DecryptResult = decrypt(
        {
            armoredPrivateKey.useArmoredStream { keyStream ->
                PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), BcKeyFingerprintCalculator())
            }
        },
        armoredMessage,
        signerPublicKeys,
    )

    /** Every private key that may decrypt, from a keyring's members or parsed legacy armor. The
     *  provider runs inside this call's failure handling, so an unparseable key is a [DecryptResult.Failed]. */
    fun decrypt(
        secretKeys: () -> PGPSecretKeyRingCollection,
        armoredMessage: String,
        signerPublicKeys: List<String>,
    ): DecryptResult = runCatching {
        val secretKeys = secretKeys()

        val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
            PGPUtil.getDecoderStream(armoredMessage.byteInputStream(Charsets.UTF_8)),
        )
        var obj = factory.nextObject()
        val encryptedList = (obj as? PGPEncryptedDataList)
            ?: (factory.nextObject() as? PGPEncryptedDataList)
            ?: return DecryptResult.Failed("not an encrypted OpenPGP message")

        // Try every recipient packet: a message may be encrypted to several keys, only one of
        // which is ours, and the packet order is the sender's choice.
        var clear: InputStream? = null
        var encrypted: PGPPublicKeyEncryptedData? = null
        for (item in encryptedList.encryptedDataObjects) {
            val pked = item as? PGPPublicKeyEncryptedData ?: continue
            // PGPSecretKeyRingCollection has no KeyIdentifier overload, so the id is routed through
            // the non-deprecated accessor; it returns the same long as the deprecated getKeyID().
            val keyId = pked.keyIdentifier.keyId
            // A hidden recipient (key id 0) names nobody: every encryption-capable private key on
            // this device is a candidate, historical members included, and a wrong one is skipped.
            val hidden = keyId == 0L
            val candidates = if (hidden) {
                secretKeys.keyRings.asSequence().flatMap { it.secretKeys.asSequence() }
                    .filter { it.publicKey.isEncryptionKey }.toList()
            } else {
                listOfNotNull(secretKeys.getSecretKey(keyId))
            }
            for (secretKey in candidates) {
                // Empty passphrase: the armored key came out of the device envelope already
                // unwrapped. A key that still needs one is not a key this device can use.
                val privateKey = secretKey.extractPrivateKey(
                    BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
                )
                val stream = if (hidden) {
                    runCatching { pked.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey)) }.getOrNull() ?: continue
                } else {
                    pked.getDataStream(BcPublicKeyDataDecryptorFactory(privateKey))
                }
                clear = stream
                encrypted = pked
                break
            }
            if (clear != null) break
        }
        if (clear == null || encrypted == null) {
            return DecryptResult.Failed("this message is not encrypted to a key on this device")
        }

        val literal = readLiteral(clear, signerPublicKeys)
            ?: return DecryptResult.Failed("this message is too large or too deeply nested to open")
        val (plaintext, signature) = literal

        // Integrity is mandatory; `||` short-circuits verify(), which throws on a tag-9 packet.
        // BC requires the whole stream to have been read before verify() can answer, so by here
        // the plaintext already exists — zero it on the failing path rather than handing an
        // unauthenticated decryption to the collector.
        if (!encrypted.isIntegrityProtected || !encrypted.verify()) {
            java.util.Arrays.fill(plaintext, 0)
            return DecryptResult.Failed("this message failed its integrity check")
        }

        DecryptResult.Ok(plaintext, signature)
    }.getOrElse { DecryptResult.Failed(it.message ?: "could not decrypt this message") }

    /** A signature that fails to parse is ABSENT; one that fails to verify is INVALID. */
    fun verifyDetached(
        armoredPublicKey: String,
        body: ByteArray,
        armoredSignature: String,
    ): RawSignature {
        val absent = RawSignature.Absent

        val signature = runCatching {
            val factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(
                PGPUtil.getDecoderStream(armoredSignature.byteInputStream(Charsets.UTF_8)),
            )
            generateSequence { factory.nextObject() }
                .filterIsInstance<PGPSignatureList>()
                .firstOrNull()
                ?.get(0)
        }.getOrNull() ?: return absent

        // From here on a signature exists, so every remaining failure is INVALID, never ABSENT.
        val key = runCatching {
            PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
                BcKeyFingerprintCalculator(),
            ).getPublicKey(signature.keyID)
        }.getOrNull() ?: return RawSignature.NoSuchKey(signature.keyID)

        val valid = runCatching {
            signature.init(BcPGPContentVerifierBuilderProvider(), key)
            signature.update(body)
            signature.verify()
        }.getOrDefault(false)

        return RawSignature.Checked(signature.keyID, valid)
    }

    private fun readLiteral(
        clear: InputStream,
        signerPublicKeys: List<String>,
    ): Pair<ByteArray, RawSignature>? {
        var factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(clear)
        var onePass: org.bouncycastle.openpgp.PGPOnePassSignature? = null
        var obj = factory.nextObject()
        var depth = 0

        while (obj != null) {
            when (obj) {
                is PGPCompressedData -> {
                    // Each layer allocates a fresh inflater; deep nesting exhausts the heap.
                    if (++depth > MAX_COMPRESSION_DEPTH) return null
                    factory = org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory(obj.dataStream)
                }
                is PGPOnePassSignatureList -> {
                    onePass = obj[0]
                }
                is PGPLiteralData -> {
                    val bytes = readAllWithLimit(obj.inputStream, MAX_DECRYPTED_PLAINTEXT_BYTES)
                        ?: return null
                    return bytes to verifyOnePass(onePass, bytes, factory, signerPublicKeys)
                }
            }
            obj = factory.nextObject()
        }
        return ByteArray(0) to RawSignature.Absent
    }

    /** Peak is 2x [limit]; [org.kysecurity.mail.MemoryBudget.PGP_PLAINTEXT_PEAK_BYTES] must match.
     *
     *  Every array this abandons is zeroed first. `copyOf` allocates, copies and drops the old
     *  array, so growing to 16 MB used to shed un-zeroed plaintext prefixes at 8 KB, 16 KB, 32 KB
     *  and so on all the way up — a whole geometric ladder of decrypted mail left for the
     *  collector, in the one function that reads decrypted mail. [decrypt] scrubs its plaintext on
     *  the integrity-failure path; this is the same rule applied to the copies. */
    internal fun readAllWithLimit(input: InputStream, limit: Int): ByteArray? {
        // One array, grown in place. The previous shape accumulated a chunk list and then joined
        // it into a full-size result, so at the first copy the chunks AND the result were both
        // live — a guaranteed 2 x plaintext, on every message. Doubling holds two arrays only
        // during a growth (old + new, at most 1.5 x the cap) or a final trim.
        var bytes = ByteArray(minOf(DEFAULT_BUFFER_SIZE, limit))
        var size = 0
        while (true) {
            if (size == bytes.size) {
                if (size >= limit) {
                    // At the ceiling. One more readable byte means the message is over the limit,
                    // and the caller must not be handed a prefix as if it were the whole thing.
                    if (input.read() < 0) return bytes
                    // Refused: nothing about this message may outlive the refusal.
                    java.util.Arrays.fill(bytes, 0)
                    return null
                }
                val grown = bytes.copyOf(minOf(bytes.size.toLong() * 2, limit.toLong()).toInt())
                java.util.Arrays.fill(bytes, 0)
                bytes = grown
            }
            val count = input.read(bytes, size, bytes.size - size)
            if (count < 0) break
            size += count
        }
        if (size == bytes.size) return bytes
        val trimmed = bytes.copyOf(size)
        java.util.Arrays.fill(bytes, 0)
        return trimmed
    }

    private fun verifyOnePass(
        onePass: org.bouncycastle.openpgp.PGPOnePassSignature?,
        body: ByteArray,
        factory: org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory,
        signerPublicKeys: List<String>,
    ): RawSignature {
        if (onePass == null) return RawSignature.Absent
        val tail = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        val key = signerPublicKeys.asSequence()
            .mapNotNull { armored ->
                runCatching {
                    PGPPublicKeyRingCollection(
                        PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                        BcKeyFingerprintCalculator(),
                    ).getPublicKey(onePass.keyID)
                }.getOrNull()
            }
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        val valid = runCatching {
            onePass.init(BcPGPContentVerifierBuilderProvider(), key)
            onePass.update(body)
            onePass.verify(tail[0])
        }.getOrDefault(false)

        return RawSignature.Checked(onePass.keyID, valid)
    }
}
