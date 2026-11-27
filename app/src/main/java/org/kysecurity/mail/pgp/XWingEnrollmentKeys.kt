package org.kysecurity.mail.pgp

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import java.security.KeyStore
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID
import kotlinx.coroutines.CancellationException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.kysecurity.mail.ProcessState

internal class EnrollmentAuthenticationCancelled : Exception()

/** One ceremony owns this holder. Only ciphertext and a public key survive between operations;
 *  process death discards them, so no pending enrollment secret needs a disk file. The AES key
 *  is non-exportable, hardware-backed and authenticated per use. BC's expanded KEM objects are
 *  transient heap objects; only the seed byte array can be reliably wiped. */
internal class XWingEnrollmentKeys(private val authenticate: suspend (Cipher) -> Cipher?) : EnrollmentKeys {
    private val alias = "$ALIAS.${UUID.randomUUID()}"
    private var wrappedSeed: ByteArray? = null
    private var iv: ByteArray? = null
    private var publicKey: ByteArray? = null

    override fun newKeyPair(): Boolean = false // prepare() requires the Activity's CryptoObject.

    override suspend fun prepare(): Boolean {
        if (!deleteKeyPair()) return false
        val generation = ProcessState.generation()
        val cipher = try {
            withContext(Dispatchers.IO) {
                if (!generateWrapKey(true) && !generateWrapKey(false)) return@withContext null
                if (generation != ProcessState.generation()) {
                    deleteKeyPair()
                    return@withContext null
                }
                runCatching { Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, wrapKey()) } }.getOrNull()
            }
        } catch (cancelled: CancellationException) {
            // A cancelled dispatcher return can discard a freshly created key. This holder owns
            // its alias, so cleanup cannot delete another ceremony's replacement key.
            deleteKeyPair()
            throw cancelled
        } ?: return false
        val authenticated = try {
            authenticate(cipher)
        } catch (cancelled: CancellationException) {
            deleteKeyPair()
            throw cancelled
        } ?: return false
        if (generation != ProcessState.generation()) return false
        val seed = ByteArray(XWING_SEED_BYTES).also { SecureRandom().nextBytes(it) }
        return try {
            // No suspension while seed bytes exist. A cancelled dispatcher return cannot strand them.
            val key = xwingPublicKey(seed)
            val encrypted = authenticated.doFinal(seed)
            publicKey = key
            iv = authenticated.iv
            wrappedSeed = encrypted
            true
        } catch (_: Exception) {
            false
        } finally {
            seed.fill(0)
        }
    }

    override fun rawPublicKey(): ByteArray? =
        publicKey?.takeIf { runCatching { store().containsAlias(alias) }.getOrDefault(false) }?.copyOf()

    override fun encodedPublicKey(): String? = rawPublicKey()?.let { Base64.getEncoder().encodeToString(it) }

    override fun sharedSecret(epk: ByteArray): ByteArray? = null // Never route X-Wing through ECDH.

    override suspend fun openEnvelope(fields: DeviceEnvelopeFields, info: ByteArray): ByteArray? {
        if (fields.version != ENVELOPE_VERSION_XWING) return null
        val encrypted = wrappedSeed ?: return null
        val nonce = iv ?: return null
        val generation = ProcessState.generation()
        val cipher = withContext(Dispatchers.IO) {
            runCatching {
                Cipher.getInstance("AES/GCM/NoPadding").apply {
                    init(Cipher.DECRYPT_MODE, wrapKey(), GCMParameterSpec(128, nonce))
                }
            }.getOrNull()
        } ?: return null
        val authenticated = authenticate(cipher) ?: throw EnrollmentAuthenticationCancelled()
        if (generation != ProcessState.generation() || wrappedSeed !== encrypted) return null
        val seed = runCatching { authenticated.doFinal(encrypted) }.getOrNull() ?: return null
        return try {
            xwingOpen(seed, fields, info)
        } finally {
            seed.fill(0)
        }
    }

    override fun deleteKeyPair(): Boolean {
        wrappedSeed?.fill(0)
        wrappedSeed = null
        iv = null
        publicKey = null
        return runCatching { store().run { deleteEntry(alias); !containsAlias(alias) } }.getOrDefault(false)
    }

    private fun wrapKey(): SecretKey {
        val key = store().getKey(alias, null) as SecretKey
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        check(info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX || info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT)
        check(info.keySize == 256 && info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == 0 &&
            info.userAuthenticationType == AUTHENTICATORS)
        return key
    }

    private fun generateWrapKey(strongBox: Boolean): Boolean = runCatching {
        val spec = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setKeySize(256)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setRandomizedEncryptionRequired(true)
            .setUserAuthenticationRequired(true)
            .setUserAuthenticationParameters(0, AUTHENTICATORS)
            .setIsStrongBoxBacked(strongBox)
            .build()
        KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").apply { init(spec) }.generateKey()
        wrapKey() // Refuse a software fallback even when generation appeared to succeed.
        true
    }.getOrDefault(false)

    companion object {
        const val ALIAS = "kypost_device_enrollment_xwing_wrap"
        private const val AUTHENTICATORS = KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
        private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        fun deleteWrapKey(): Boolean = runCatching {
            store().run {
                val owned = aliases().asSequence().filter { it == ALIAS || it.startsWith("$ALIAS.") }.toList()
                owned.forEach { deleteEntry(it) }
                owned.none { containsAlias(it) }
            }
        }.getOrDefault(false)
    }
}
