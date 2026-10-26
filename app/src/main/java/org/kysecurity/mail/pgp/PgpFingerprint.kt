package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import java.io.ByteArrayInputStream

/** Hashes the key's own bytes; a server-supplied fingerprint string has no tie to the key. */
object PgpFingerprint {

    /** Space-grouped uppercase hex, or null — callers must treat null as "reject this key". */
    fun compute(armoredPublicKey: String): String? = runCatching {
        val decoder = PGPUtil.getDecoderStream(ByteArrayInputStream(armoredPublicKey.toByteArray(Charsets.UTF_8)))
        val factory = JcaPGPObjectFactory(decoder)
        val ring = factory.nextObject() as? PGPPublicKeyRing ?: return@runCatching null

        // Reject anything past the first object: an appended second key ring is otherwise invisible.
        if (factory.nextObject() != null) return@runCatching null

        val primary = ring.publicKey
        val subkeysAllBound = ring.publicKeys.asSequence()
            .filter { !it.isMasterKey }
            .all { subkey -> hasValidBindingSignature(primary, subkey, requireStrongDigest = false) }
        if (!subkeysAllBound) return@runCatching null

        format(primary.fingerprint)
    }.getOrNull()

    /** For this device's own key, which needs no binding check. */
    internal fun of(key: org.bouncycastle.openpgp.PGPPublicKey): String = format(key.fingerprint)

    private fun format(bytes: ByteArray): String =
        bytes.joinToString("") { "%02X".format(it) }.chunked(4).joinToString(" ")
}

/** Bc verifier, not Jca: Android has no EdDSA KeyFactory and every ed25519 subkey read unbound. */
internal fun hasValidBindingSignature(
    primary: org.bouncycastle.openpgp.PGPPublicKey,
    subkey: org.bouncycastle.openpgp.PGPPublicKey,
    requireStrongDigest: Boolean,
): Boolean {
    val verifierProvider = org.bouncycastle.openpgp.operator.bc
        .BcPGPContentVerifierBuilderProvider()
    val signatures = subkey.getSignaturesOfType(
        org.bouncycastle.openpgp.PGPSignature.SUBKEY_BINDING,
    )
    while (signatures.hasNext()) {
        val signature = signatures.next()
        if (requireStrongDigest && !PgpStrengthPolicy.digestAllowed(signature.hashAlgorithm)) continue
        val verified = runCatching {
            signature.init(verifierProvider, primary)
            signature.verifyCertification(primary, subkey)
        }.getOrDefault(false)
        if (verified) return true
    }
    return false
}
