// See AppLockStore: androidx.security-crypto is deprecated in full with no replacement API.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.pgp

import android.content.Context
import android.content.SharedPreferences
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.system.Os
import android.system.OsConstants
import android.util.Base64
import android.util.Log
import org.kysecurity.mail.MemoryBudget
import java.io.File
import java.io.FileOutputStream
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

private const val ANDROID_KEYSTORE = "AndroidKeyStore"
private const val KEY_IV = "envelope_iv"
private const val KEY_CT = "envelope_ct"
private const val ACK_GENERATION = "ack_generation"
private const val ACK_FINGERPRINT = "ack_fingerprint"
private const val TEARDOWN_REPORT = "teardown_report"

/** Same shape as the encrypted-prefs opener: three reads in all before absence counts. */
private const val ABSENCE_RECHECKS = 2
private const val ABSENCE_RECHECK_BACKOFF_MS = 120L

private const val IV_BYTES = 12
private const val GCM_TAG_BYTES = 16

/** The sealed plaintext is the bounded enrollment output; GCM appends its tag. */
private const val CIPHERTEXT_MAX_BYTES = MemoryBudget.PGP_SECRET_KEY_OUTPUT_BYTES + GCM_TAG_BYTES
private const val RECORD_MIN_BYTES = 1 + IV_BYTES + GCM_TAG_BYTES
private const val RECORD_MAX_BYTES = 1 + IV_BYTES + CIPHERTEXT_MAX_BYTES

/** NO_WRAP base64 grows 3 bytes to 4 characters, rounded up to a whole quantum. */
private const val LEGACY_CT_MAX_CHARS = (CIPHERTEXT_MAX_BYTES + 2) / 3 * 4
private const val LEGACY_IV_MAX_CHARS = (IV_BYTES + 2) / 3 * 4

/** A sealed record as read back. Not a `data class`: equality over the arrays would be identity.
 *  Destructures as `(iv, ciphertext)` for the callers that predate [kind]. */
internal class StoredRecord(val iv: ByteArray, val ciphertext: ByteArray, val kind: VaultRecordKind) {
    operator fun component1() = iv
    operator fun component2() = ciphertext
}

/**
 * AES-256-GCM Keystore key. DEVICE_CREDENTIAL is allowed so it survives a biometric change.
 *
 * The sealed record is one file: version byte, 12-byte IV, ciphertext. It is replaced by writing
 * a sibling, syncing it, and renaming over the old record, so a crash or a full disk leaves the
 * previous complete record readable. Vaults written before this format live in the encrypted
 * preference file; they are read in place and retired only after a replacement is on disk.
 */
internal class EnrollmentVault(
    context: Context,
    /** Test seam only: a Keystore that lies about alias presence is the fault [ensureKey] guards. */
    private val keyStore: () -> KeyStore = { KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) } },
) {

    private val appContext = context.applicationContext
    private val prefs: SharedPreferences by lazy { buildPrefs() }
    private val recordFile = File(appContext.filesDir, RECORD_FILE)
    private val pendingFile = File(appContext.filesDir, "$RECORD_FILE.new")
    private val legacyFile = File(File(appContext.dataDir, "shared_prefs"), "$PREFS_FILE.xml")

    /** Plain preferences: the generation and fingerprint are what the server lists on the owner's
     *  device page, not secrets. A tampered value only makes the acknowledgement fail closed. */
    private val ackPrefs: SharedPreferences by lazy { appContext.getSharedPreferences(ACK_PREFS_FILE, Context.MODE_PRIVATE) }

    private enum class KeyState { MATCHES, ABSENT, UNUSABLE }

    /**
     * False when the device has no secure lock screen — the envelope's protection *is* that screen.
     *
     * A key the Keystore confirms absent (the OS deletes it when the lock screen is removed) can
     * never open a record again, so regenerating discards that dead record. While a record exists,
     * "confirms" means [absenceCorroborated]: one negative read is not proof. A key that is present
     * but unusable — it will not inspect, or no longer matches [generate]'s spec — might still open
     * the record, so while any record exists, or the store cannot be read, this fails closed rather
     * than regenerate over it. Only "Remove from this device" may discard such a record.
     */
    fun ensureKey(): Boolean {
        val state = keyState()
        if (state == KeyState.MATCHES) return true
        val previous = runCatching { stored() }.getOrElse {
            Log.e("EnrollmentVault", "Vault store unreadable; not regenerating the key over it", it)
            return false
        }
        if (previous != null) {
            if (state == KeyState.UNUSABLE) {
                Log.e("EnrollmentVault", "Vault key unusable while a sealed record exists; refusing to regenerate")
                return false
            }
            if (!absenceCorroborated()) {
                Log.e("EnrollmentVault", "Vault key absence not corroborated; keeping the sealed record")
                return false
            }
        }
        return generate(strongBox = true) || generate(strongBox = false)
    }

    /** AndroidKeyStore is routinely unavailable for a few hundred milliseconds around boot, and a
     *  "no such alias" answer from that window looks like a removed lock screen. Re-read under the
     *  same backoff `openEncryptedPrefs` uses, then require the Keystore to prove it is answering
     *  by round-tripping the master key every encrypted store in this app is sealed under. */
    private fun absenceCorroborated(): Boolean {
        repeat(ABSENCE_RECHECKS) {
            Thread.sleep(ABSENCE_RECHECK_BACKOFF_MS)
            if (keyState() != KeyState.ABSENT) return false
        }
        return org.kysecurity.mail.security.keystoreAnswers()
    }

    /** [KeyState.MATCHES] only when a key exists AND still carries every property [generate]
     *  establishes. */
    private fun keyState(): KeyState = runCatching {
        val ks = keyStore()
        if (!ks.containsAlias(ALIAS)) return KeyState.ABSENT
        val key = ks.getKey(ALIAS, null) as? SecretKey ?: return KeyState.UNUSABLE
        val info = SecretKeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        val matches = info.isUserAuthenticationRequired &&
            info.keySize == 256 &&
            info.userAuthenticationType == EXPECTED_AUTHENTICATORS &&
            // 0 = per-use auth. A time-based validity window would let a key sealed under a live
            // authentication keep operating for some interval afterwards, which is not what this
            // vault promises.
            info.userAuthenticationValidityDurationSeconds == 0
        if (matches) KeyState.MATCHES else KeyState.UNUSABLE
    }.getOrElse {
        // An unreadable key is not a usable key, and not proof that it is gone either.
        Log.i("EnrollmentVault", "Existing vault key could not be inspected", it)
        KeyState.UNUSABLE
    }

    /** Generates the vault key and **clears any stored record**: a stale record makes the probe
     *  lie. [ensureKey] only reaches this when no record exists or none can ever open again. */
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
        // Clear first so an interruption leaves "no key, no record" rather than "new key, stale record".
        clearRecords()
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

    /**
     * True only once the complete record is synced to disk, renamed into place, and the rename
     * itself is synced: a rename is directory metadata, and until the directory is fsynced an
     * unclean shutdown can revert it to the previous record while the ceremony has already told
     * the server this device is enrolled. False leaves whatever was stored before — file or legacy
     * preferences — and the vault key untouched. androidx `AtomicFile` is not used because its
     * `finishWrite` logs a failed sync or rename instead of reporting it.
     */
    fun store(iv: ByteArray, ciphertext: ByteArray, kind: VaultRecordKind = VaultRecordKind.LEGACY_ARMOR): Boolean {
        if (iv.size != IV_BYTES || ciphertext.size !in GCM_TAG_BYTES..CIPHERTEXT_MAX_BYTES) {
            Log.e("EnrollmentVault", "Refusing to store a malformed record")
            return false
        }
        val record = ByteArray(1 + IV_BYTES + ciphertext.size).also {
            it[0] = kind.recordVersion
            iv.copyInto(it, 1)
            ciphertext.copyInto(it, 1 + IV_BYTES)
        }
        val written = runCatching {
            FileOutputStream(pendingFile).use { out ->
                out.write(record)
                out.fd.sync()
            }
            Files.move(
                pendingFile.toPath(),
                recordFile.toPath(),
                StandardCopyOption.ATOMIC_MOVE,
                StandardCopyOption.REPLACE_EXISTING,
            )
            syncDirectory(recordFile.parentFile!!)
        }.onFailure {
            Log.e("EnrollmentVault", "Could not store the sealed record", it)
            runCatching { Files.deleteIfExists(pendingFile.toPath()) }
        }.isSuccess
        // A new record is a new delivery; whatever was acknowledged for the old one is no longer true.
        if (written) {
            retireLegacyRecord()
            clearKeyringAck()
        }
        return written
    }

    /** Stored after the keyring record it describes, so the worker can restate the acknowledgement
     *  without opening the vault. */
    fun storeKeyringAck(ack: EnrollmentReport.Keyring): Boolean =
        ackPrefs.edit().putLong(ACK_GENERATION, ack.materialGeneration).putString(ACK_FINGERPRINT, ack.fingerprint).commit()

    fun keyringAck(): EnrollmentReport.Keyring? {
        val fingerprint = ackPrefs.getString(ACK_FINGERPRINT, null) ?: return null
        if (!ackPrefs.contains(ACK_GENERATION)) return null
        return EnrollmentReport.Keyring(ackPrefs.getLong(ACK_GENERATION, 0L), fingerprint)
    }

    /** False on a failed write, which `commit()` reports without throwing. */
    private fun clearKeyringAck(): Boolean = ackPrefs.edit().clear().commit()

    /** Set by `EnrollmentTeardown` after [destroy], read by the worker. [store] clears it: a new
     *  record is a new enrollment and the old teardown no longer describes the device. */
    fun markTeardownReport(): Boolean = ackPrefs.edit().putBoolean(TEARDOWN_REPORT, true).commit()
    fun teardownReportPending(): Boolean = ackPrefs.getBoolean(TEARDOWN_REPORT, false)
    fun clearTeardownReport(): Boolean = ackPrefs.edit().remove(TEARDOWN_REPORT).commit()

    /** `java.io` cannot open a directory, so this goes through the libc bindings; a failed fsync
     *  throws `ErrnoException` and counts as a failed store. */
    private fun syncDirectory(dir: File) {
        val fd = Os.open(dir.path, OsConstants.O_RDONLY, 0)
        try {
            Os.fsync(fd)
        } finally {
            Os.close(fd)
        }
    }

    /** Best effort: the file is authoritative once it exists, so a surviving legacy copy is stale,
     *  not dangerous, and [destroy] still finds it. */
    private fun retireLegacyRecord() {
        if (!legacyFile.exists()) return
        runCatching {
            prefs.edit().clear().commit()
            appContext.deleteSharedPreferences(PREFS_FILE)
        }.onFailure { Log.w("EnrollmentVault", "Legacy envelope store not retired", it) }
    }

    /** Null proves no record exists in either format. Failed or incomplete reads must never
     *  authorize a current-only enrollment seal over a recoverable historical vault. Background
     *  probes catch failures at their own boundary; the opener maps them to OpenOutcome.Failed.
     *  Reading never rewrites: a legacy record stays where it is until [store] replaces it. */
    fun stored(): StoredRecord? {
        if (recordFile.exists()) return parseRecord()
        if (!legacyFile.exists()) return null
        val iv = prefs.getString(KEY_IV, null)
        val ct = prefs.getString(KEY_CT, null)
        if (iv == null && ct == null) return null
        check(iv != null && ct != null) { "Incomplete enrollment vault" }
        check(iv.length <= LEGACY_IV_MAX_CHARS && ct.length <= LEGACY_CT_MAX_CHARS) { "Oversized enrollment vault" }
        val decodedIv = Base64.decode(iv, Base64.NO_WRAP)
        val decodedCt = Base64.decode(ct, Base64.NO_WRAP)
        check(decodedIv.size == IV_BYTES && decodedCt.size >= GCM_TAG_BYTES) { "Invalid enrollment vault" }
        // Preference records predate the format byte and only ever held armor.
        return StoredRecord(decodedIv, decodedCt, VaultRecordKind.LEGACY_ARMOR)
    }

    private fun parseRecord(): StoredRecord {
        val length = recordFile.length()
        check(length in RECORD_MIN_BYTES..RECORD_MAX_BYTES) { "Invalid enrollment vault" }
        val record = recordFile.readBytes()
        check(record.size.toLong() == length) { "Invalid enrollment vault" }
        val kind = VaultRecordKind.entries.firstOrNull { it.recordVersion == record[0] }
        checkNotNull(kind) { "Invalid enrollment vault" }
        return StoredRecord(record.copyOfRange(1, 1 + IV_BYTES), record.copyOfRange(1 + IV_BYTES, record.size), kind)
    }

    fun hasBlob(): Boolean = runCatching {
        recordFile.exists() || (legacyFile.exists() && prefs.contains(KEY_CT))
    }.getOrDefault(false)

    /** Throws when a record cannot be removed, so a caller never proceeds over a stale one. */
    private fun clearRecords() {
        Files.deleteIfExists(recordFile.toPath())
        Files.deleteIfExists(pendingFile.toPath())
        clearKeyringAck()
        if (legacyFile.exists()) check(prefs.edit().clear().commit()) { "legacy record not cleared" }
    }

    /** Destroys the sealed record in every format and the vault key, and **reports what it could
     *  not destroy**. */
    fun destroy(): List<String> {
        val failed = mutableListOf<String>()
        runCatching {
            Files.deleteIfExists(recordFile.toPath())
            Files.deleteIfExists(pendingFile.toPath())
        }.onFailure { Log.e("EnrollmentVault", "Could not delete the sealed record", it) }
        if (recordFile.exists() || pendingFile.exists()) failed += "deleteRecordFile"
        if (!runCatching { clearKeyringAck() }.getOrDefault(false)) failed += "clearAck"
        if (legacyFile.exists()) {
            runCatching { prefs.edit().clear().commit() }
                .onFailure { failed += "clearBlob"; Log.e("EnrollmentVault", "Could not clear the blob", it) }
            // deleteSharedPreferences returns false when the file is still there — the one signal that
            // the sealed envelope survived. Discarding it was how this reported success over a live blob.
            val fileGone = runCatching { appContext.deleteSharedPreferences(PREFS_FILE) }.getOrDefault(false)
            if (!fileGone && runCatching { hasBlob() }.getOrDefault(true)) failed += "deletePrefsFile"
        }
        runCatching {
            val ks = keyStore()
            ks.deleteEntry(ALIAS)
            if (ks.containsAlias(ALIAS)) error("alias survived deleteEntry")
        }.onFailure { failed += "deleteKey"; Log.e("EnrollmentVault", "Could not delete the vault key", it) }
        return failed
    }

    internal fun secretKey(): SecretKey = keyStore().getKey(ALIAS, null) as SecretKey

    /** Resets the store if the Tink keyset is undecryptable; failing closed reads as "not enrolled".
     *  A legacy record under a keyset nothing can open again was already unrecoverable. */
    private fun buildPrefs(): SharedPreferences =
        org.kysecurity.mail.security.openEncryptedPrefs(appContext, PREFS_FILE) {
            Log.e("EnrollmentVault", "Envelope store keyset is undecryptable", it)
        }

    companion object {
        /** Named once, so [generate] and [keyState] cannot drift — the drift was the bug. */
        private const val EXPECTED_AUTHENTICATORS =
            KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL

        const val ALIAS = "kypost_device_envelope_seal"
        const val PREFS_FILE = "device_envelope_secure"
        const val RECORD_FILE = "device_envelope.bin"
        const val ACK_PREFS_FILE = "device_envelope_ack"
    }
}
