package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider
import java.io.ByteArrayOutputStream

/**
 * [pinned] with a key revocation taken from [synced], or null when there is none to take. Only a
 * revocation of the SAME primary key, verifiable against the pinned primary key, is taken, and
 * only that signature: no subkey, user id or other material crosses from the synced copy, so a
 * synced copy can withdraw a pinned key but never change what it is.
 */
internal fun withVerifiedRevocation(pinned: String, synced: String): String? = runCatching {
    val pinnedRing = singleRing(pinned) ?: return null
    val syncedRing = singleRing(synced) ?: return null
    val primary = pinnedRing.publicKey
    if (!primary.fingerprint.contentEquals(syncedRing.publicKey.fingerprint)) return null
    if (primary.hasRevocation()) return null
    val revocation = syncedRing.publicKey.getSignaturesOfType(PGPSignature.KEY_REVOCATION).asSequence()
        .filterIsInstance<PGPSignature>()
        .firstOrNull { signature ->
            runCatching {
                signature.init(BcPGPContentVerifierBuilderProvider(), primary)
                signature.verifyCertification(primary)
            }.getOrDefault(false)
        } ?: return null
    val revoked = PGPPublicKeyRing.insertPublicKey(pinnedRing, PGPPublicKey.addCertification(primary, revocation))
    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { it.write(revoked.encoded) }
    out.toString(Charsets.UTF_8.name())
}.getOrNull()

/** The primary key of [armored] carries a revocation. Read on pinned bytes, which this device
 *  wrote: a revocation is only added to them by [withVerifiedRevocation]. */
internal fun isPrimaryRevoked(armored: String): Boolean =
    runCatching { singleRing(armored)?.publicKey?.hasRevocation() == true }.getOrDefault(false)

private fun singleRing(armored: String): PGPPublicKeyRing? {
    val factory = JcaPGPObjectFactory(PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)))
    val ring = factory.nextObject() as? PGPPublicKeyRing ?: return null
    return ring.takeIf { factory.nextObject() == null }
}
