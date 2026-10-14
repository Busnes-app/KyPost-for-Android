package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyPairGenerator
import java.security.KeyStore
import javax.crypto.Cipher

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val PREFS_FILE = "app_lock_biometric"
private const val KEY_SEALED = "sealed_credential_keys"

class BiometricUnlock(val cipher: Cipher, val sealed: ByteArray)

/** Biometric only: device credential would make the lock-screen PIN a way past the app PIN. */
class BiometricUnlockVault(context: Context) : BiometricKeySealer {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy {
        appContext.getSharedPreferences(PREFS_FILE, Context.MODE_PRIVATE)
    }

    /** Re-sealing on every PIN unlock (while biometric unlock is on) recovers an invalidated key. */
    override fun seal(keys: CredentialKeys) {
        val publicKey = ensureKey()
        if (publicKey == null) {
            clearBlob()
            return
        }
        runCatching {
            val sealed = CredentialEnvelope.seal(keys, CredentialEnvelope.encryptCipher(publicKey))
            prefs.edit().putString(KEY_SEALED, Base64.encodeToString(sealed, Base64.NO_WRAP)).commit()
        }.onFailure {
            Log.e("BiometricUnlockVault", "Could not seal the credential keys", it)
            clearBlob()
        }
    }

    /** Null when biometric unlock is not on offer; drops an invalidated key. Blocking: Keystore. */
    override fun prepareUnlock(): BiometricUnlock? {
        val sealed = storedBlob() ?: return null
        val privateKey = runCatching {
            keyStore().getKey(ALIAS, null) as? java.security.PrivateKey
        }.getOrNull() ?: return null

        return try {
            BiometricUnlock(CredentialEnvelope.decryptCipher(privateKey), sealed)
        } catch (e: KeyPermanentlyInvalidatedException) {
            Log.i("BiometricUnlockVault", "Biometric enrollment changed; dropping the sealed keys", e)
            destroy()
            null
        } catch (e: Exception) {
            Log.e("BiometricUnlockVault", "Could not prepare a biometric unlock", e)
            null
        }
    }

    /** Removes the key and the sealed blob, naming what it could not remove so
     *  [SecurityWipe] can report an incomplete wipe rather than a clean one. */
    override fun destroy(): List<String> {
        val failed = mutableListOf<String>()
        runCatching { prefs.edit().clear().commit() }
            .onFailure { failed += "clearSealedKeys" }
        runCatching {
            val ks = keyStore()
            ks.deleteEntry(ALIAS)
            if (ks.containsAlias(ALIAS)) error("alias survived deleteEntry")
        }.onFailure { failed += "deleteBiometricKey" }
        return failed
    }

    private fun storedBlob(): ByteArray? = runCatching {
        prefs.getString(KEY_SEALED, null)?.let { Base64.decode(it, Base64.NO_WRAP) }
    }.getOrNull()

    private fun clearBlob() {
        runCatching { prefs.edit().remove(KEY_SEALED).commit() }
    }

    /** The public half, generating the pair if it is absent. Null when this device cannot hold the
     *  key — no strong biometric enrolled, or no secure lock screen at all. */
    private fun ensureKey(): java.security.PublicKey? = runCatching {
        val ks = keyStore()
        if (!ks.containsAlias(ALIAS)) generate()
        ks.getCertificate(ALIAS)?.publicKey
    }.getOrElse {
        Log.i("BiometricUnlockVault", "No biometric-bound key on this device", it)
        null
    }

    private fun generate() {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setDigests(KeyProperties.DIGEST_SHA256)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_RSA_OAEP)
            .setKeySize(2048)
            .setUserAuthenticationRequired(true)
            // 0 = per-use auth, satisfied through a BiometricPrompt.CryptoObject.
            .setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            .setInvalidatedByBiometricEnrollment(true)
            .build()
        KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA, ANDROID_KEYSTORE)
            .apply { initialize(spec) }
            .generateKeyPair()
    }

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    companion object {
        const val ALIAS = "kypost_applock_biometric"
    }
}
