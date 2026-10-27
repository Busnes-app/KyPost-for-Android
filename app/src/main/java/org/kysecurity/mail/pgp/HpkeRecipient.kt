package org.kysecurity.mail.pgp

import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/*
 * RFC 9180 HPKE, recipient side, one suite: mode_base, DHKEM(P-256, HKDF-SHA256) (0x0010),
 * HKDF-SHA256 (0x0001), AES-256-GCM (0x0002). HPKE libraries take the raw private key; the
 * enrollment key never leaves the Keystore, so DH(skR, pkE) comes in as [dh], the Keystore's ECDH.
 * Everything else here is the RFC's arithmetic over that output and public inputs.
 */

private const val MODE_BASE: Byte = 0x00
private const val N_SECRET = 32 // §7.1 DHKEM(P-256) Nsecret and Ndh
private const val N_K = 32 // §7.3 AES-256-GCM
private const val N_N = 12
private const val N_T = 16
private const val N_H = 32 // §7.2 HKDF-SHA256

private val HPKE_V1 = "HPKE-v1".toByteArray(Charsets.US_ASCII)

// §4.1: suite_id = "KEM" || I2OSP(kem_id, 2)
private val KEM_SUITE_ID = "KEM".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x00, 0x10)

// §5.1: suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)
private val HPKE_SUITE_ID = "HPKE".toByteArray(Charsets.US_ASCII) + byteArrayOf(0x00, 0x10, 0x00, 0x01, 0x00, 0x02)

/** §5.1 context for one recipient. [exporterSecret] is derived for the RFC vector check only. */
internal class HpkeContext(val sharedSecret: ByteArray, val key: ByteArray, val baseNonce: ByteArray, val exporterSecret: ByteArray) {
    fun wipe() = listOf(sharedSecret, key, baseNonce, exporterSecret).forEach { it.fill(0) }
}

/** §5.1.1 SetupBaseR. Null when [enc] is not a P-256 point or [dh] refuses it. */
internal fun hpkeSetupBaseR(enc: ByteArray, pkRm: ByteArray, info: ByteArray, dh: (ByteArray) -> ByteArray?): HpkeContext? {
    // §4.1 Decap: pkE = DeserializePublicKey(enc), validated (§7.1.4) before the Keystore sees it.
    if (enc.size != 65 || enc[0] != 0x04.toByte() || !isP256Point(enc) || pkRm.size != 65) return null
    val dhOut = dh(enc) ?: return null
    try {
        if (dhOut.size != N_SECRET) return null
        // §4.1 ExtractAndExpand(dh, kem_context = enc || pkRm)
        val eaePrk = labeledExtract(KEM_SUITE_ID, ByteArray(0), "eae_prk", dhOut)
        val sharedSecret = labeledExpand(KEM_SUITE_ID, eaePrk, "shared_secret", enc + pkRm, N_SECRET)
        eaePrk.fill(0)
        return keyScheduleBase(sharedSecret, info)
    } finally {
        dhOut.fill(0)
    }
}

/** §5.1 KeySchedule for mode_base: psk and psk_id are empty. */
private fun keyScheduleBase(sharedSecret: ByteArray, info: ByteArray): HpkeContext {
    val pskIdHash = labeledExtract(HPKE_SUITE_ID, ByteArray(0), "psk_id_hash", ByteArray(0))
    val infoHash = labeledExtract(HPKE_SUITE_ID, ByteArray(0), "info_hash", info)
    val context = byteArrayOf(MODE_BASE) + pskIdHash + infoHash
    val secret = labeledExtract(HPKE_SUITE_ID, sharedSecret, "secret", ByteArray(0))
    return try {
        HpkeContext(
            sharedSecret = sharedSecret,
            key = labeledExpand(HPKE_SUITE_ID, secret, "key", context, N_K),
            baseNonce = labeledExpand(HPKE_SUITE_ID, secret, "base_nonce", context, N_N),
            exporterSecret = labeledExpand(HPKE_SUITE_ID, secret, "exp", context, N_H),
        )
    } finally {
        secret.fill(0)
    }
}

/** §5.2 ContextR.Open at seq 0: nonce = base_nonce XOR I2OSP(0, Nn) = base_nonce. Throws on a bad tag. */
internal fun HpkeContext.openFirst(aad: ByteArray, ct: ByteArray): ByteArray {
    if (ct.size < N_T) throw AEADBadTagException("ciphertext shorter than the tag")
    return Cipher.getInstance("AES/GCM/NoPadding").run {
        init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(N_T * 8, baseNonce))
        updateAAD(aad)
        doFinal(ct)
    }
}

/** §6.1 single-shot Open with the empty aad KyPost uses: the device binding travels in [info].
 *  Null means not sealed for this key and binding; never retried. */
internal fun hpkeOpenBase(enc: ByteArray, pkRm: ByteArray, info: ByteArray, ct: ByteArray, dh: (ByteArray) -> ByteArray?): ByteArray? {
    val context = hpkeSetupBaseR(enc, pkRm, info, dh) ?: return null
    return try {
        context.openFirst(ByteArray(0), ct)
    } catch (e: AEADBadTagException) {
        android.util.Log.w("HpkeRecipient", "Device envelope failed authentication; it was not sealed for this device")
        null
    } catch (e: java.security.GeneralSecurityException) {
        android.util.Log.e("HpkeRecipient", "Device envelope could not be opened", e)
        null
    } finally {
        context.wipe()
    }
}

// §4: LabeledExtract(salt, label, ikm) = Extract(salt, "HPKE-v1" || suite_id || label || ikm)
private fun labeledExtract(suiteId: ByteArray, salt: ByteArray, label: String, ikm: ByteArray): ByteArray =
    // RFC 5869 §2.2: an empty salt is HashLen zeros, which SecretKeySpec accepts and "" does not.
    hmac(if (salt.isEmpty()) ByteArray(N_H) else salt).run {
        update(HPKE_V1); update(suiteId); update(label.toByteArray(Charsets.US_ASCII)); update(ikm)
        doFinal()
    }

// §4: LabeledExpand(prk, label, info, L) = Expand(prk, I2OSP(L, 2) || "HPKE-v1" || suite_id || label || info, L)
private fun labeledExpand(suiteId: ByteArray, prk: ByteArray, label: String, info: ByteArray, length: Int): ByteArray {
    val labeledInfo = byteArrayOf(0, length.toByte()) + HPKE_V1 + suiteId + label.toByteArray(Charsets.US_ASCII) + info
    // RFC 5869 §2.3 Expand. Every length here is at most one HashLen block, so T(1) suffices.
    require(length in 1..N_H)
    val block = hmac(prk).run { update(labeledInfo); update(1.toByte()); doFinal() }
    return block.copyOf(length).also { block.fill(0) }
}

private fun hmac(key: ByteArray): Mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(key, "HmacSHA256")) }
