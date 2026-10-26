package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
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

        PublicKeyAlgorithmTags.ECDH,
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
}
