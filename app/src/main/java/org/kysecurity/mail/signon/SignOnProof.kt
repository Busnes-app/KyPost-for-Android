package org.kysecurity.mail.signon

import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PublicKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.Base64

/**
 * Proof of possession for KyIdentity sign-on (`kypost-signon-pop/1`): the ID token names
 * [thumb] of an ephemeral key, and the relay requires a signature by that key over [message].
 */
object SignOnProof {
    /** One fresh software P-256 key pair per attempt; held in memory only, never stored. */
    fun newKeyPair(): KeyPair =
        KeyPairGenerator.getInstance("EC").apply { initialize(ECGenParameterSpec("secp256r1")) }.generateKeyPair()

    /** base64url-no-pad SHA-256 of the SPKI DER: the `cnf` value KyAuth puts in the token. */
    fun thumb(publicKey: PublicKey): String = b64url(sha256(publicKey.encoded))

    fun message(origin: String, idToken: String): ByteArray =
        "kypost-signon-pop/1\n$origin\n${b64url(sha256(idToken.toByteArray(Charsets.US_ASCII)))}".toByteArray(Charsets.UTF_8)

    /** Std base64 DER `SHA256withECDSA` signature over [message]. */
    fun sign(keyPair: KeyPair, origin: String, idToken: String): String =
        Signature.getInstance("SHA256withECDSA").run {
            initSign(keyPair.private)
            update(message(origin, idToken))
            Base64.getEncoder().encodeToString(sign())
        }

    fun proofKey(publicKey: PublicKey): String = Base64.getEncoder().encodeToString(publicKey.encoded)

    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun b64url(bytes: ByteArray) = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
}
