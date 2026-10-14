package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import java.util.Date

/** [addresses] is the server's binding — never re-derive it from the key's forgeable User IDs. */
internal data class SignerKey(
    val addresses: List<String>,
    val publicKey: String,
    /** Read by nothing that decides a verdict — see [signatureStateFor]. Do not read it. */
    val verified: Boolean,
    val source: String,
    val conflict: Boolean,
)

/** A ring is dropped whole when its primary is revoked or expired; the only expiry gate. */
internal fun signerKeyIdsOf(armoredPublicKey: String, now: Date = Date()): Set<Long> = runCatching {
    val rings = PGPPublicKeyRingCollection(
        PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
        BcKeyFingerprintCalculator(),
    )
    rings.keyRings.asSequence()
        .filter { it.publicKey.isUsableAt(now) }
        .flatMap { ring ->
            val primary = ring.publicKey
            ring.publicKeys.asSequence()
                .filter { it.isUsableAt(now) }
                // A subkey counts only if the PRIMARY vouches for it; BC does not check bindings.
                .filter { it.isMasterKey || hasValidBindingSignature(primary, it) }
                // And it must be a key that may sign at all. A signature verifying under an
                // encryption-only subkey is not a signature from that identity.
                .filter { it.canSign(primary) }
        }
        .map { it.keyID }
        .toSet()
}.getOrDefault(emptySet())

private fun org.bouncycastle.openpgp.PGPPublicKey.isUsableAt(now: Date): Boolean =
    !hasRevocation() && !isExpiredAt(now)

/** Key flags, not `isEncryptionKey()` — that answers "can this algorithm sign", not "may it". */
private fun org.bouncycastle.openpgp.PGPPublicKey.canSign(
    primary: org.bouncycastle.openpgp.PGPPublicKey,
): Boolean {
    val flags = keyFlagsAssertedBy(primary)
    if (flags != 0) {
        return flags and org.bouncycastle.bcpg.sig.KeyFlags.SIGN_DATA != 0
    }
    // No key flags asserted at all: fall back to what the algorithm can do.
    return isEncryptionKey.not() || isMasterKey
}

/** Only [primary]'s signatures, and only hashed subpackets — an unhashed flag grants nothing. */
private fun org.bouncycastle.openpgp.PGPPublicKey.keyFlagsAssertedBy(
    primary: org.bouncycastle.openpgp.PGPPublicKey,
): Int {
    var flags = 0
    val signatures = signatures
    while (signatures.hasNext()) {
        val signature = signatures.next() as? org.bouncycastle.openpgp.PGPSignature ?: continue
        if (signature.keyID != primary.keyID) continue
        val vectors = signature.hashedSubPackets ?: continue
        if (vectors.hasSubpacket(org.bouncycastle.bcpg.SignatureSubpacketTags.KEY_FLAGS)) {
            flags = flags or vectors.keyFlags
        }
    }
    return flags
}

private fun org.bouncycastle.openpgp.PGPPublicKey.isExpiredAt(now: Date): Boolean {
    val validSeconds = getValidSeconds()
    if (validSeconds <= 0) return false
    val createdAt = creationTime.time
    if (validSeconds > (Long.MAX_VALUE - createdAt) / 1_000L) return false
    return createdAt + validSeconds * 1_000L <= now.time
}

/** [confirmed] is the only input that can produce [PgpSignatureState.VERIFIED_CONFIRMED].
 *  [pinned]: held in `recipient_pins`, not the synced fallback for an address with no pin. */
internal data class LocalSignerKey(val publicKey: String, val confirmed: Boolean, val pinned: Boolean = false)

internal fun interface LocalSignerKeyLookup {
    /** Empty when this device holds no key for [address] — including when [address] is blank. */
    suspend fun keysFor(address: String): List<LocalSignerKey>
}

/** Local keys win. With none, a relay key can show a signature is bad, never that the sender is
 *  known: no VERIFIED_* state without a key this device holds, and `verified` is ignored. */
internal fun signatureStateFor(
    signature: RawSignature,
    serverKeys: List<SignerKey>,
    localKeys: List<LocalSignerKey> = emptyList(),
): PgpSignatureState {
    if (!signature.present) return PgpSignatureState.NONE

    if (localKeys.isNotEmpty()) {
        val signedBy = localKeys.filter { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
        // We hold a key for this sender and the message was not signed with it. Not
        // SIGNER_UNKNOWN: "we have no opinion" is false here, we have one and it disagrees.
        if (signedBy.isEmpty()) return PgpSignatureState.KEY_CHANGED
        return verdictFor(signature, confirmed = signedBy.any { it.confirmed })
    }

    // A conflict outranks a good key: two entries for one address means one of them changed.
    if (serverKeys.any { it.conflict }) return PgpSignatureState.KEY_CHANGED

    val signedByRelayKey = serverKeys.any { signature.signerKeyId in signerKeyIdsOf(it.publicKey) }
    val bad = signature is RawSignature.Checked && !signature.verified
    return if (signedByRelayKey && bad) PgpSignatureState.INVALID else PgpSignatureState.SIGNER_UNKNOWN
}

/** [RawSignature.NoSuchKey] must never reach INVALID: nothing was checked, nothing is accused. */
private fun verdictFor(signature: RawSignature, confirmed: Boolean): PgpSignatureState =
    when (signature) {
        is RawSignature.Absent -> PgpSignatureState.NONE
        is RawSignature.NoSuchKey -> PgpSignatureState.SIGNER_UNKNOWN
        is RawSignature.Checked -> when {
            !signature.verified -> PgpSignatureState.INVALID
            confirmed -> PgpSignatureState.VERIFIED_CONFIRMED
            else -> PgpSignatureState.VERIFIED_SEEN_BEFORE
        }
    }
