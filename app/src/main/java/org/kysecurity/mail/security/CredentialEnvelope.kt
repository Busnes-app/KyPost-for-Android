package org.kysecurity.mail.security

import java.security.PrivateKey
import java.security.PublicKey
import java.security.spec.MGF1ParameterSpec
import javax.crypto.Cipher
import javax.crypto.spec.OAEPParameterSpec
import javax.crypto.spec.PSource
import javax.crypto.spec.SecretKeySpec

private const val AES_KEY_BYTES = 32
private const val TRANSFORMATION = "RSA/ECB/OAEPPadding"

/** AndroidKeyStore's OAEP uses MGF1-SHA-1 whatever the transformation name says. */
private val OAEP = OAEPParameterSpec(
    "SHA-256",
    "MGF1",
    MGF1ParameterSpec.SHA1,
    PSource.PSpecified.DEFAULT,
)

/** Proof that these keys came out of [CredentialEnvelope.open] — i.e. out of a Cipher that a
 *  strong biometric had already authorized.
 *
 *  Private constructor plus an internal issuer, the same shape as [AppLockManager.DecisionToken]
 *  and for the same reason. [AppLockManager.unlockWithBiometric] unlocks the mailbox and clears
 *  the failed-attempt ladder; it used to take a bare [CredentialKeys] from any caller, so the
 *  entire security property lived in UnlockActivity having remembered to run a BiometricPrompt
 *  first and nothing required it to. `SourceRulesTest` keeps [issue] to this file. */
class BiometricProof private constructor(internal val keys: CredentialKeys) {
    internal companion object {
        fun issue(keys: CredentialKeys) = BiometricProof(keys)
    }
}

object CredentialEnvelope {

    fun encryptCipher(publicKey: PublicKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, publicKey, OAEP) }

    fun decryptCipher(privateKey: PrivateKey): Cipher =
        Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.DECRYPT_MODE, privateKey, OAEP) }

    fun seal(keys: CredentialKeys, cipher: Cipher): ByteArray =
        cipher.doFinal(keys.current.encoded + keys.legacy.encoded)

    /** [cipher] must be the one a BiometricPrompt CryptoObject just authorized; that is what the
     *  returned [BiometricProof] attests to, and it is the only way to mint one. */
    fun open(sealed: ByteArray, cipher: Cipher): BiometricProof? {
        val plaintext = runCatching { cipher.doFinal(sealed) }.getOrNull() ?: return null
        if (plaintext.size != AES_KEY_BYTES * 2) return null
        return BiometricProof.issue(
            CredentialKeys(
                current = SecretKeySpec(plaintext, 0, AES_KEY_BYTES, "AES"),
                legacy = SecretKeySpec(plaintext, AES_KEY_BYTES, AES_KEY_BYTES, "AES"),
            ),
        )
    }
}

interface BiometricKeySealer {
    fun seal(keys: CredentialKeys)

    /** Null when nothing is sealed or the key is gone. */
    fun prepareUnlock(): BiometricUnlock?

    /** Names what it could not remove. */
    fun destroy(): List<String>
}

/** For a manager with no biometric hardware behind it: tests, and nothing else. */
object NoBiometricSealer : BiometricKeySealer {
    override fun seal(keys: CredentialKeys) = Unit
    override fun prepareUnlock(): BiometricUnlock? = null
    override fun destroy(): List<String> = emptyList()
}
