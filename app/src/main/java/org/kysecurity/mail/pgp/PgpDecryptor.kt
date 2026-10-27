package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPOnePassSignatureList
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection
import org.bouncycastle.openpgp.PGPSignature
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

/** Keeps absent, unknown-key, policy-disabled and checked signatures distinct. */
internal sealed class RawSignature {
    object Absent : RawSignature()

    /** Signed, but no key with this id was among the ones offered — so nothing was checked. Never
     *  an accusation; see [PgpSignatureState.SIGNER_UNKNOWN]. */
    data class NoSuchKey(val keyId: Long) : RawSignature()

    /** A retained key or signature uses a policy-disabled algorithm; no validity claim. */
    data class Unchecked(val keyId: Long) : RawSignature()

    /** [forAnotherRecipient]: the signature names its intended recipients (RFC 9580 subpacket 35)
     *  and none is the key this device decrypted with (detached: any key it holds). */
    data class Checked(val keyId: Long, val verified: Boolean, val forAnotherRecipient: Boolean = false) : RawSignature()

    val present: Boolean get() = this !is Absent

    /** Only a checked signature can be valid. */
    val valid: Boolean get() = (this as? Checked)?.verified == true

    val signerKeyId: Long get() = when (this) {
        is Absent -> 0L
        is NoSuchKey -> keyId
        is Unchecked -> keyId
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
    internal const val REFUSED_CIPHER = "this message uses a cipher KyPost refuses"
    internal const val REFUSED_KEY = "this message is encrypted to a key below KyPost's strength requirement"

    fun decrypt(
        /** The enrolled key as a [CharArray], never a `String`: [EnrollmentSession] holds it in a
         *  wipeable array precisely so no caller has to mint an immortal copy to reach this. */
        armoredPrivateKey: CharArray,
        armoredMessage: String,
        /** From the address book, never the key inside the message; empty means unverifiable. */
        signerPublicKeys: List<String>,
        refuseLegacy: Boolean = false,
    ): DecryptResult = decrypt(
        {
            armoredPrivateKey.useArmoredStream { keyStream ->
                PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyStream), BcKeyFingerprintCalculator())
            }
        },
        armoredMessage,
        signerPublicKeys,
        refuseLegacy,
    )

    /** Every private key that may decrypt, from a keyring's members or parsed legacy armor. The
     *  provider runs inside this call's failure handling, so an unparseable key is a [DecryptResult.Failed].
     *
     *  [refuseLegacy] is the user's strict setting: no decryption with a key below
     *  [PgpStrengthPolicy.keyAllowed], and no 64-bit-block session cipher. */
    fun decrypt(
        secretKeys: () -> PGPSecretKeyRingCollection,
        armoredMessage: String,
        signerPublicKeys: List<String>,
        refuseLegacy: Boolean = false,
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
        var ours: List<ByteArray> = emptyList()
        var refused = false
        for (item in encryptedList.encryptedDataObjects) {
            val pked = item as? PGPPublicKeyEncryptedData ?: continue
            // PGPSecretKeyRingCollection has no KeyIdentifier overload, so the id is routed through
            // the non-deprecated accessor; it returns the same long as the deprecated getKeyID().
            val keyId = pked.keyIdentifier.keyId
            // A hidden recipient (key id 0) names nobody: every encryption-capable private key on
            // this device is a candidate, historical members included, and a wrong one is skipped.
            val hidden = keyId == 0L
            val candidates = if (hidden) {
                secretKeys.keyRings.asSequence().flatMap { ring -> ring.secretKeys.asSequence().map { ring to it } }
                    .filter { it.second.publicKey.isEncryptionKey }.toList()
            } else {
                listOfNotNull(secretKeys.getSecretKeyRing(keyId)?.let { ring -> ring.getSecretKey(keyId)?.let { ring to it } })
            }
            for ((ring, secretKey) in candidates) {
                if (refuseLegacy && !(PgpStrengthPolicy.keyAllowed(ring.publicKey) && PgpStrengthPolicy.keyAllowed(secretKey.publicKey))) {
                    refused = true
                    continue
                }
                // Empty passphrase: the armored key came out of the device envelope already
                // unwrapped. A key that still needs one is not a key this device can use.
                val privateKey = secretKey.extractPrivateKey(
                    BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
                )
                val factory = BcPublicKeyDataDecryptorFactory(privateKey)
                val stream = if (hidden) {
                    runCatching { pked.getDataStream(factory) }.getOrNull() ?: continue
                } else {
                    pked.getDataStream(factory)
                }
                // The session key is now known to be ours; refuse its cipher before reading a byte.
                if (!PgpStrengthPolicy.archiveCipherAllowed(pked.getSymmetricAlgorithm(factory), strict = refuseLegacy)) {
                    runCatching { stream.close() }
                    return DecryptResult.Failed(REFUSED_CIPHER)
                }
                clear = stream
                encrypted = pked
                // Senders name the primary (RFC 9580); the decrypting subkey is accepted too.
                ours = listOf(ring.publicKey.fingerprint, secretKey.publicKey.fingerprint)
                break
            }
            if (clear != null) break
        }
        if (clear == null || encrypted == null) {
            return DecryptResult.Failed(if (refused) REFUSED_KEY else "this message is not encrypted to a key on this device")
        }

        val literal = readLiteral(clear, signerPublicKeys, ours)
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

    /** A signature that fails to parse is ABSENT; one that fails to verify is INVALID.
     *  [heldKeys]: fingerprints of every key this device holds, see [heldKeyFingerprints]. */
    fun verifyDetached(
        armoredPublicKey: String,
        body: ByteArray,
        armoredSignature: String,
        heldKeys: List<ByteArray>,
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

        // Keep a declared signature present even when its key is unknown or policy-disabled.
        val (primary, key) = signerKeyOf(armoredPublicKey, signature.keyID)
            ?: return RawSignature.NoSuchKey(signature.keyID)

        if (!PgpStrengthPolicy.memberAllowed(primary, key) || !PgpStrengthPolicy.digestAllowed(signature.hashAlgorithm)) {
            return RawSignature.Unchecked(signature.keyID)
        }

        val valid = runCatching {
            signature.init(BcPGPContentVerifierBuilderProvider(), key)
            signature.update(body)
            signature.verify()
        }.getOrDefault(false)

        return RawSignature.Checked(signature.keyID, valid, forAnotherRecipient = namesOnlyOthers(signature, heldKeys))
    }

    private fun signerKeyOf(armored: String, keyId: Long): Pair<org.bouncycastle.openpgp.PGPPublicKey, org.bouncycastle.openpgp.PGPPublicKey>? =
        runCatching {
            val ring = PGPPublicKeyRingCollection(
                PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)),
                BcKeyFingerprintCalculator(),
            ).getPublicKeyRing(keyId) ?: return null
            ring.publicKey to (ring.getPublicKey(keyId) ?: return null)
        }.getOrNull()

    /** Every key, primary and subkey, of every ring this device holds. */
    fun heldKeyFingerprints(secretKeys: PGPSecretKeyRingCollection): List<ByteArray> =
        secretKeys.keyRings.asSequence().flatMap { it.publicKeys.asSequence() }.map { it.fingerprint }.toList()

    /** True when the signature names its intended recipients (RFC 9580 subpacket 35) and none is
     *  in [ours]. Hashed only: an unhashed subpacket is not covered by the signature. */
    private fun namesOnlyOthers(signature: PGPSignature, ours: List<ByteArray>): Boolean {
        val intended = signature.hashedSubPackets?.intendedRecipientFingerprints.orEmpty()
        return intended.isNotEmpty() && intended.none { named -> ours.any { it.contentEquals(named.fingerprint) } }
    }

    private fun readLiteral(
        clear: InputStream,
        signerPublicKeys: List<String>,
        decryptedWith: List<ByteArray>,
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
                    return bytes to verifyOnePass(onePass, bytes, factory, signerPublicKeys, decryptedWith)
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
        decryptedWith: List<ByteArray>,
    ): RawSignature {
        if (onePass == null) return RawSignature.Absent
        val tail = generateSequence { factory.nextObject() }
            .filterIsInstance<PGPSignatureList>()
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        val (primary, key) = signerPublicKeys.asSequence()
            .mapNotNull { armored -> signerKeyOf(armored, onePass.keyID) }
            .firstOrNull()
            ?: return RawSignature.NoSuchKey(onePass.keyID)

        if (!PgpStrengthPolicy.memberAllowed(primary, key) ||
            !PgpStrengthPolicy.digestAllowed(onePass.hashAlgorithm) ||
            !PgpStrengthPolicy.digestAllowed(tail[0].hashAlgorithm)
        ) return RawSignature.Unchecked(onePass.keyID)

        val metadataMatches = onePass.hashAlgorithm == tail[0].hashAlgorithm &&
            onePass.keyAlgorithm == tail[0].keyAlgorithm && onePass.keyID == tail[0].keyID
        val valid = metadataMatches && runCatching {
            onePass.init(BcPGPContentVerifierBuilderProvider(), key)
            onePass.update(body)
            onePass.verify(tail[0])
        }.getOrDefault(false)

        return RawSignature.Checked(onePass.keyID, valid, forAnotherRecipient = namesOnlyOthers(tail[0], decryptedWith))
    }
}
