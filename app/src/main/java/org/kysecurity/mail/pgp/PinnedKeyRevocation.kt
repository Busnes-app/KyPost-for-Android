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
 * [pinned] with the revocations taken from [synced], or null when there is none to take. A synced
 * copy of the SAME primary key may revoke that primary or any subkey the pin already holds,
 * matched by fingerprint; each revocation must verify against the pinned primary. Only those
 * signatures cross: no subkey, user id or other material, so a synced copy can withdraw pinned
 * keys but never change what they are.
 */
internal fun withVerifiedRevocation(pinned: String, synced: String): String? = runCatching {
    val pinnedRing = singleRing(pinned) ?: return null
    val syncedRing = singleRing(synced) ?: return null
    val primary = pinnedRing.publicKey
    if (!primary.fingerprint.contentEquals(syncedRing.publicKey.fingerprint)) return null
    var ring = pinnedRing
    for (key in pinnedRing.publicKeys.asSequence().toList()) {
        val syncedKey = syncedRing.getPublicKey(key.fingerprint) ?: continue
        val held = revocationsOf(key).map { it.encoded.toList() }.toSet()
        val taken = revocationsOf(syncedKey).filter { it.encoded.toList() !in held && verifies(it, primary, key) }
        if (taken.isEmpty()) continue
        ring = PGPPublicKeyRing.insertPublicKey(ring, taken.fold(ring.getPublicKey(key.keyID)) { k, s -> PGPPublicKey.addCertification(k, s) })
    }
    if (ring === pinnedRing) return null
    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { it.write(ring.encoded) }
    out.toString(Charsets.UTF_8.name())
}.getOrNull()

/** The primary key of [armored] carries a revocation that verifies against it. A packet alone is
 *  not enough: pins seeded by `MIGRATION_12_13` and synced fallback keys hold bytes this device
 *  never checked. */
internal fun isPrimaryRevoked(armored: String): Boolean = runCatching {
    val primary = singleRing(armored)?.publicKey ?: return false
    revocationsOf(primary).any { verifies(it, primary, primary) }
}.getOrDefault(false)

private fun revocationsOf(key: PGPPublicKey): List<PGPSignature> =
    key.getSignaturesOfType(if (key.isMasterKey) PGPSignature.KEY_REVOCATION else PGPSignature.SUBKEY_REVOCATION)
        .asSequence().filterIsInstance<PGPSignature>().toList()

private fun verifies(signature: PGPSignature, primary: PGPPublicKey, key: PGPPublicKey): Boolean = runCatching {
    signature.init(BcPGPContentVerifierBuilderProvider(), primary)
    if (key.isMasterKey) signature.verifyCertification(primary) else signature.verifyCertification(primary, key)
}.getOrDefault(false)

private fun singleRing(armored: String): PGPPublicKeyRing? {
    val factory = JcaPGPObjectFactory(PGPUtil.getDecoderStream(armored.byteInputStream(Charsets.UTF_8)))
    val ring = factory.nextObject() as? PGPPublicKeyRing ?: return null
    return ring.takeIf { factory.nextObject() == null }
}
