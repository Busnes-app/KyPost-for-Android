package org.kysecurity.mail.pgp

import org.bouncycastle.crypto.AsymmetricCipherKeyPair
import org.bouncycastle.crypto.hpke.HPKE
import org.bouncycastle.pqc.crypto.xwing.XWingPrivateKeyParameters

internal const val XWING_PUBLIC_KEY_BYTES = 1216
internal const val XWING_ENCAPSULATION_BYTES = 1120
internal const val XWING_SEED_BYTES = 32
internal const val XWING_ENVELOPE_ALG = "HPKE-Base-XWing-SHA256-A256GCM"

/** BC's lightweight API avoids Android's stripped JCE provider. The library owns the KEM and
 *  RFC 9180 schedule; no hand-written hybrid combiner or private-key serialization. */
private fun xwingHpke() = HPKE(HPKE.mode_base, HPKE.kem_X_WING, HPKE.kdf_HKDF_SHA256, HPKE.aead_AES_GCM256)

internal fun xwingKeyPair(seed: ByteArray): AsymmetricCipherKeyPair {
    require(seed.size == XWING_SEED_BYTES)
    val privateKey = XWingPrivateKeyParameters(seed)
    return AsymmetricCipherKeyPair(privateKey.publicKeyParameters, privateKey)
}

internal fun xwingPublicKey(seed: ByteArray): ByteArray = xwingHpke().serializePublicKey(xwingKeyPair(seed).public)

/** Single-shot HPKE with empty aad; the verified delivery context is bound in info. BC's expanded
 *  private-key objects cannot be erased; caller wipes the seed and drops these transient objects. */
internal fun xwingOpen(seed: ByteArray, fields: DeviceEnvelopeFields, info: ByteArray): ByteArray? = runCatching {
    require(fields.version == ENVELOPE_VERSION_XWING && fields.epk.size == XWING_ENCAPSULATION_BYTES)
    xwingHpke().setupBaseR(fields.epk, xwingKeyPair(seed), info).open(ByteArray(0), fields.ct)
}.getOrNull()

/** Companion sealer for interoperability checks and callers with an already validated key. */
internal fun xwingSeal(publicKey: ByteArray, info: ByteArray, plaintext: ByteArray): DeviceEnvelopeFields {
    require(publicKey.size == XWING_PUBLIC_KEY_BYTES)
    val hpke = xwingHpke()
    val sender = hpke.setupBaseS(hpke.deserializePublicKey(publicKey), info)
    return DeviceEnvelopeFields(ENVELOPE_VERSION_XWING, sender.encapsulation, sender.seal(ByteArray(0), plaintext))
}
