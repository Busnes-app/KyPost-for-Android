package org.kysecurity.mail.security

import android.content.Context
import android.util.Base64
import org.kysecurity.mail.data.DATABASE_NAME
import org.kysecurity.mail.data.DatabaseMigration
import java.io.File
import java.security.SecureRandom
import java.util.Arrays

private const val TAG = "DatabaseKey"
private const val PREFS_FILE = "db_key_secure"
private const val KEY_PASSPHRASE = "db_passphrase"
private const val PASSPHRASE_BYTES = 32

/** SQLCipher passphrase: 32 random bytes, not PIN-derived — the DB opens with no PIN entered. */
internal object DatabaseKey {

    /** Serialises the check-mint-store sequence below. Two threads reaching a first open together
     *  both read no passphrase, both call [discardUnopenableDatabase] — which DELETES the database
     *  — and both mint; whichever loses the `commit()` has handed its caller a passphrase that is
     *  on nobody's disk, so the database it opens can never be reopened. */
    private val mintLock = Any()

    /** Base64 so the byte helper and the ATTACH ... KEY SQL text derive the same key. */
    fun passphrase(context: Context): String = synchronized(mintLock) {
        val appContext = context.applicationContext
        val prefs = openEncryptedPrefs(appContext, PREFS_FILE) {
            android.util.Log.e(TAG, "Database key store keyset is undecryptable", it)
        }
        prefs.getString(KEY_PASSPHRASE, null)?.let { return it }
        discardUnopenableDatabase(appContext)

        val fresh = ByteArray(PASSPHRASE_BYTES).also { SecureRandom().nextBytes(it) }
        val encoded = Base64.encodeToString(fresh, Base64.NO_WRAP)
        Arrays.fill(fresh, 0)
        // commit(), like every other security-relevant write in this package: a process death
        // before an async flush would leave a database encrypted under a key nothing remembers.
        prefs.edit().putString(KEY_PASSPHRASE, encoded).commit()
        return encoded
    }

    /** No stored passphrase with an encrypted file present means the keyset reset; the file can
     *  never open. A plaintext file is a pre-encryption install that [DatabaseMigration] converts. */
    private fun discardUnopenableDatabase(appContext: Context) {
        if (!unopenableWithoutKey(appContext.getDatabasePath(DATABASE_NAME))) return
        android.util.Log.e(TAG, "The database key was reset; $DATABASE_NAME can never be opened again")
        recordCredentialReset(appContext, DATABASE_NAME)
        appContext.deleteDatabase(DATABASE_NAME)
    }

    internal fun unopenableWithoutKey(file: File): Boolean =
        file.exists() && !DatabaseMigration.isPlaintext(file)

    /** Part of [SecurityWipe]: an encrypted database is only as gone as its key. Returns the step
     *  names it could not remove, matching the other teardown helpers. */
    fun destroy(context: Context): List<String> {
        val appContext = context.applicationContext
        return if (appContext.deleteSharedPreferences(PREFS_FILE)) {
            emptyList()
        } else {
            val file = java.io.File(java.io.File(appContext.dataDir, "shared_prefs"), "$PREFS_FILE.xml")
            if (file.exists()) listOf("deleteDatabaseKey") else emptyList()
        }
    }

}
