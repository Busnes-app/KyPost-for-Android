// See AppLockStore: androidx.security-crypto is deprecated in full with no replacement API.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.pgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.util.Base64
import android.util.Log
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_IV = "envelope_iv"
private const val KEY_CT = "envelope_ct"

/** AES-256-GCM Keystore key. DEVICE_CREDENTIAL is allowed so it survives a biometric change. */
internal class EnrollmentVault(context: Context) {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildPrefs() }

    /** False when the device has no secure lock screen — the envelope's protection *is* that screen. */
    fun ensureKey(): Boolean {
        if (existingKeyMatchesSpec()) return true
        return generate(strongBox = true) || generate(strongBox = false)
    }

    /**
     * True only when a key exists AND still carries every property [generate] establishes.
     */
    private fun existingKeyMatchesSpec(): Boolean = runCatching {
        val ks = keyStore()
        if (!ks.containsAlias(ALIAS)) return false
        val key = ks.getKey(ALIAS, null) as? SecretKey ?: return false
        val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        info.isUserAuthenticationRequired &&
            info.keySize == 256 &&
            info.userAuthenticationType == EXPECTED_AUTHENTICATORS &&
            // 0 = per-use auth. A time-based validity window would let a key sealed under a live
            // authentication keep operating for some interval afterwards, which is not what this
            // vault promises.
            info.userAuthenticationValidityDurationSeconds == 0
    }.getOrElse {
        // An unreadable key is not a usable key. Regenerating is the safe direction: it costs a
        // re-enrollment, where adopting an unverifiable key costs the property the vault exists for.
        Log.i("EnrollmentVault", "Existing vault key could not be inspected; regenerating", it)
        false
    }

    /** Generates the vault key and **clears any stored blob**: a stale blob makes the probe lie. */
    private fun generate(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(
            ALIAS,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            // 0 = per-use auth, satisfied through a BiometricPrompt.CryptoObject.
            .setUserAuthenticationParameters(0, EXPECTED_AUTHENTICATORS)
            .apply { if (strongBox) setIsStrongBoxBacked(true) }
            .build()
        // Clear first so an interruption leaves "no key, no blob" rather than "new key, stale blob".
        prefs.edit().clear().commit()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEYSTORE)
            .apply { init(spec) }
            .generateKey()
        true
    }.getOrElse {
        if (strongBox) Log.i("EnrollmentVault", "StrongBox unavailable, falling back to TEE")
        else Log.e("EnrollmentVault", "Could not generate the vault key", it)
        false
    }

    fun sealCipher(): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, secretKey()) }
    }.getOrNull()

    fun openCipher(iv: ByteArray): Cipher? = runCatching {
        Cipher.getInstance("AES/GCM/NoPadding")
            .apply { init(Cipher.DECRYPT_MODE, secretKey(), GCMParameterSpec(128, iv)) }
    }.getOrNull()

    fun store(iv: ByteArray, ciphertext: ByteArray) {
        prefs.edit()
            .putString(KEY_IV, Base64.encodeToString(iv, Base64.NO_WRAP))
            .putString(KEY_CT, Base64.encodeToString(ciphertext, Base64.NO_WRAP))
            .commit()
    }

    /** Null proves both fields are absent. Failed or incomplete reads must never authorize a
     *  current-only enrollment seal over a recoverable historical vault. Background probes catch
     *  failures at their own boundary; the opener maps them to OpenOutcome.Failed. */
    fun stored(): Pair<ByteArray, ByteArray>? {
        val iv = prefs.getString(KEY_IV, null)
        val ct = prefs.getString(KEY_CT, null)
        if (iv == null && ct == null) return null
        check(iv != null && ct != null) { "Incomplete enrollment vault" }
        val decodedIv = Base64.decode(iv, Base64.NO_WRAP)
        val decodedCt = Base64.decode(ct, Base64.NO_WRAP)
        check(decodedIv.size == 12 && decodedCt.size >= 16) { "Invalid enrollment vault" }
        return decodedIv to decodedCt
    }

    fun hasBlob(): Boolean = runCatching { prefs.contains(KEY_CT) }.getOrDefault(false)

    /** Destroys the sealed blob and the vault key, and **reports what it could not destroy**. */
    fun destroy(): List<String> {
        val failed = mutableListOf<String>()
        runCatching { prefs.edit().clear().commit() }
            .onFailure { failed += "clearBlob"; Log.e("EnrollmentVault", "Could not clear the blob", it) }
        // deleteSharedPreferences returns false when the file is still there — the one signal that
        // the sealed envelope survived. Discarding it was how this reported success over a live blob.
        val fileGone = runCatching { appContext.deleteSharedPreferences(PREFS_FILE) }.getOrDefault(false)
        if (!fileGone && runCatching { hasBlob() }.getOrDefault(true)) failed += "deletePrefsFile"
        runCatching {
            val ks = keyStore()
            ks.deleteEntry(ALIAS)
            if (ks.containsAlias(ALIAS)) error("alias survived deleteEntry")
        }.onFailure { failed += "deleteKey"; Log.e("EnrollmentVault", "Could not delete the vault key", it) }
        return failed
    }

    internal fun secretKey(): SecretKey = keyStore().getKey(ALIAS, null) as SecretKey

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    /** Resets the store if the Tink keyset is undecryptable; failing closed reads as "not enrolled". */
    private fun buildPrefs(): SharedPreferences =
        org.kysecurity.mail.security.openEncryptedPrefs(appContext, PREFS_FILE) {
            Log.e("EnrollmentVault", "Envelope store keyset is undecryptable", it)
        }

    companion object {
        /** Named once, so [generate] and [existingKeyMatchesSpec] cannot drift — the drift was the
         *  bug. */
        private const val EXPECTED_AUTHENTICATORS =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL

        const val ALIAS = "kypost_device_envelope_seal"
        const val PREFS_FILE = "device_envelope_secure"
    }
}
