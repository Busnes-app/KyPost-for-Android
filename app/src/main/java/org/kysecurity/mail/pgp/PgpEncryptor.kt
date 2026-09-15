package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.CompressionAlgorithmTags
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedDataGenerator
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPLiteralDataGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDataEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyKeyEncryptionMethodGenerator
import java.io.ByteArrayOutputStream
import java.security.SecureRandom
import java.util.Date

internal sealed class EncryptResult {
    data class Ok(val armored: String) : EncryptResult()

    data class Failed(val message: String) : EncryptResult()
}

/** Bc* operators, never Jce*: Android's stripped "BC" JCE provider makes the Jce path differ. */
internal object PgpEncryptor {

    /** Legacy armor: the first (current) ring signs. A key that will not parse is unusable, never
     *  silently unsigned. */
    fun encrypt(
        plaintext: ByteArray,
        recipientPublicKeys: List<String>,
        /** Armored private key to sign with, or null to encrypt without signing. A [CharArray]
         *  for the same reason [PgpDecryptor.decrypt]'s is. */
        armoredSigningKey: CharArray?,
    ): EncryptResult {
        val ring = armoredSigningKey?.let { armor ->
            runCatching { armor.useArmoredStream(::orderedSecretKeyRings)?.firstOrNull() }.getOrNull()
                ?: return EncryptResult.Failed("the signing key is unusable")
        }
        return encrypt(plaintext, recipientPublicKeys, ring)
    }

    fun encrypt(
        plaintext: ByteArray,
        /** Armored recipient public keys. Empty is refused rather than producing a message nobody
         *  can open. */
        recipientPublicKeys: List<String>,
        /** The one ring that signs, or null to encrypt without signing. Only this ring's own
         *  signing key is considered: a historical member is never a fallback. */
        signingRing: PGPSecretKeyRing?,
    ): EncryptResult = runCatching {
        if (plaintext.size > MAX_DECRYPTED_PLAINTEXT_BYTES) {
            return EncryptResult.Failed("this message is too large to encrypt")
        }
        if (recipientPublicKeys.isEmpty()) {
            return EncryptResult.Failed("no recipient keys to encrypt to")
        }

        // An unparseable recipient key is a hard failure, never a skip.
        val encryptionKeys = recipientPublicKeys.map { armored ->
            encryptionKeyOf(armored) ?: return EncryptResult.Failed("a recipient key is unusable")
        }

        val generator = PGPEncryptedDataGenerator(
            BcPGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                // Integrity protection is not optional: PgpDecryptor fails closed on a message
                // without it, so omitting it would make our own output unreadable by our own reader.
                .setWithIntegrityPacket(true)
                .setSecureRandom(SecureRandom()),
        )
        encryptionKeys.forEach { generator.addMethod(BcPublicKeyKeyEncryptionMethodGenerator(it)) }

        val signer = signingRing?.let {
            signatureGeneratorFor(it) ?: return EncryptResult.Failed("the signing key is unusable")
        }

        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armoredOut ->
            generator.open(armoredOut, ByteArray(BUFFER_BYTES)).use { encryptedOut ->
                val compressor = PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP)
                val compressedOut = compressor.open(encryptedOut)

                // One-pass contract: one-pass header, then literal data, then signature.
                signer?.generateOnePassVersion(false)?.encode(compressedOut)

                val literalGenerator = PGPLiteralDataGenerator()
                literalGenerator.open(
                    compressedOut,
                    // BINARY, not TEXT: we already emit canonical CRLF ourselves, and TEXT
                    // invites a second round of line-ending canonicalization on the way out.
                    PGPLiteralData.BINARY,
                    "",
                    plaintext.size.toLong(),
                    Date(),
                ).use { literalOut -> literalOut.write(plaintext) }
                signer?.update(plaintext)
                // The literal packet must be closed before the signature packet is written, or the
                // signature lands inside it.
                literalGenerator.close()

                signer?.generate()?.encode(compressedOut)
                compressor.close()
            }
        }
        EncryptResult.Ok(out.toString(Charsets.UTF_8.name()))
    }.getOrElse { EncryptResult.Failed(it.message ?: "could not encrypt this message") }

    /** Legacy armor: the first (current) ring. */
    fun ownPublicKey(armoredPrivateKey: CharArray): String? = runCatching {
        armoredPrivateKey.useArmoredStream(::orderedSecretKeyRings)?.firstOrNull()?.let { ownPublicKey(it) }
    }.getOrNull()

    /** Derived from the private key, never fetched; the whole ring, since only the subkey encrypts. */
    fun ownPublicKey(ring: PGPSecretKeyRing): String? = runCatching {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { armoredOut ->
            PGPPublicKeyRing(ring.publicKeys.asSequence().toList()).encode(armoredOut)
        }
        out.toString(Charsets.UTF_8.name())
    }.getOrNull()

    /** Only the subkey encrypts, and the relay-supplied blob is validated locally before use. */
    private fun encryptionKeyOf(armoredPublicKey: String): PGPPublicKey? = runCatching {
        if (PgpFingerprint.compute(armoredPublicKey) == null) return@runCatching null
        PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.asSequence()
            .flatMap { ring -> ring.publicKeys.asSequence() }
            .filter { it.isEncryptionKey && !it.hasRevocation() && !it.hasExpired() }
            // Newest, not "last in the serialisation": a ring may carry a rotated-away subkey.
            .maxByOrNull { it.creationTime.time }
    }.getOrNull()

    /** `validSeconds == 0` means no expiry; [PGPPublicKey.isEncryptionKey] ignores expiry. */
    private fun PGPPublicKey.hasExpired(nowMillis: Long = System.currentTimeMillis()): Boolean {
        val validSeconds = validSeconds
        if (validSeconds <= 0L) return false
        return nowMillis > creationTime.time + validSeconds * 1000L
    }

    /** Empty passphrase: the key came out of the device envelope already unwrapped. A revoked or
     *  expired signing key is unusable, not a reason to look elsewhere. */
    private fun signatureGeneratorFor(ring: PGPSecretKeyRing): PGPSignatureGenerator? = runCatching {
        val secretKey = ring.secretKeys.asSequence()
            .firstOrNull { it.isSigningKey && !it.publicKey.hasRevocation() && !it.publicKey.hasExpired() }
            ?: return null

        val privateKey = secretKey.extractPrivateKey(
            BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(CharArray(0)),
        )
        PGPSignatureGenerator(
            BcPGPContentSignerBuilder(secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256),
            secretKey.publicKey,
        ).apply { init(PGPSignature.BINARY_DOCUMENT, privateKey) }
    }.getOrNull()

    private const val BUFFER_BYTES = 1 shl 16
}
