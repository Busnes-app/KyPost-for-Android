package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ECDHPublicBCPGKey
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPPublicKey

/** Policy for new encryption, signing and positive signature trust, not archival decryption. */
internal object PgpStrengthPolicy {
    // Existing v4 RSA role tags remain readable; the policy does not generate those tags.
    @Suppress("DEPRECATION")
    fun keyAllowed(key: PGPPublicKey): Boolean = when (key.algorithm) {
        PublicKeyAlgorithmTags.RSA_GENERAL,
        PublicKeyAlgorithmTags.RSA_ENCRYPT,
        PublicKeyAlgorithmTags.RSA_SIGN,
        -> key.bitStrength >= 2048

        // An ECDH key also names the KDF hash and key-wrap cipher every message to it uses.
        PublicKeyAlgorithmTags.ECDH -> key.bitStrength >= 224 &&
            (key.publicKeyPacket.key as? ECDHPublicBCPGKey)?.let {
                digestAllowed(it.hashAlgorithm.toInt()) && it.symmetricKeyAlgorithm.toInt() in AES
            } == true

        PublicKeyAlgorithmTags.ECDSA,
        PublicKeyAlgorithmTags.EDDSA_LEGACY,
        PublicKeyAlgorithmTags.X25519,
        PublicKeyAlgorithmTags.X448,
        PublicKeyAlgorithmTags.Ed25519,
        PublicKeyAlgorithmTags.Ed448,
        -> key.bitStrength >= 224

        else -> false
    }

    fun memberAllowed(primary: PGPPublicKey, key: PGPPublicKey): Boolean =
        keyAllowed(primary) && keyAllowed(key) &&
            (key.isMasterKey || hasValidBindingSignature(primary, key, requireStrongDigest = true))

    fun digestAllowed(algorithm: Int): Boolean = when (algorithm) {
        HashAlgorithmTags.SHA256,
        HashAlgorithmTags.SHA384,
        HashAlgorithmTags.SHA512,
        HashAlgorithmTags.SHA3_256,
        HashAlgorithmTags.SHA3_512,
        -> true

        else -> false
    }

    private val AES = setOf(SymmetricKeyAlgorithmTags.AES_128, SymmetricKeyAlgorithmTags.AES_192, SymmetricKeyAlgorithmTags.AES_256)

    /** Session ciphers an already-received message may use. Plaintext (NULL), single DES, SAFER
     *  and unknown ids never open; [strict] also refuses the 64-bit-block legacy ciphers. */
    fun archiveCipherAllowed(algorithm: Int, strict: Boolean): Boolean = when (algorithm) {
        SymmetricKeyAlgorithmTags.AES_128,
        SymmetricKeyAlgorithmTags.AES_192,
        SymmetricKeyAlgorithmTags.AES_256,
        SymmetricKeyAlgorithmTags.TWOFISH,
        SymmetricKeyAlgorithmTags.CAMELLIA_128,
        SymmetricKeyAlgorithmTags.CAMELLIA_192,
        SymmetricKeyAlgorithmTags.CAMELLIA_256,
        -> true

        SymmetricKeyAlgorithmTags.IDEA,
        SymmetricKeyAlgorithmTags.TRIPLE_DES,
        SymmetricKeyAlgorithmTags.CAST5,
        SymmetricKeyAlgorithmTags.BLOWFISH,
        -> !strict

        else -> false
    }
}
