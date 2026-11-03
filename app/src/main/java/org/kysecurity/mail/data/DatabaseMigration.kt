package org.kysecurity.mail.data

import android.content.Context
import net.zetetic.database.sqlcipher.SQLiteDatabase
import java.io.File

private const val TAG = "DatabaseMigration"

/** The 16 bytes SQLite writes at offset 0: `SQLite format 3` followed by a terminating NUL. */
private val SQLITE_MAGIC = "SQLite format 3".toByteArray(Charsets.US_ASCII) + 0

// Nothing in the SQLCipher AAR loads libsqlcipher.so; without this the first Room query throws.
internal val sqlCipherLoaded: Boolean by lazy {
    runCatching { System.loadLibrary("sqlcipher") }
        .onFailure { android.util.Log.e(TAG, "Could not load libsqlcipher.so", it) }
        .isSuccess
}

// Converted rather than discarded: `pending_contact_changes` holds edits that exist nowhere else.
internal object DatabaseMigration {

    /** False means the file on disk is still plaintext; callers MUST check before opening it. */
    fun encryptIfNeeded(context: Context, databaseName: String, passphrase: String): Boolean {
        val appContext = context.applicationContext
        val plain = appContext.getDatabasePath(databaseName)
        val temp = File(plain.parentFile, "$databaseName.encrypting")

        if (recoverInterrupted(plain, temp, passphrase)) return true
        if (!plain.exists()) return true
        if (!isPlaintext(plain)) return true

        android.util.Log.i(TAG, "Converting $databaseName to an encrypted database")
        cleanUp(temp)
        if (!sqlCipherLoaded) return false

        return runCatching {
            val userVersion = exportToTemp(plain, temp, passphrase)

            // Verify BEFORE anything is replaced: an export that produced an unopenable file must
            // not be allowed to overwrite the only readable copy of the user's pending edits.
            check(versionUnder(temp, passphrase) == userVersion) { "converted database failed verification" }

            // Before the rename, so the encrypted file is never paired with a foreign WAL.
            deleteJournals(plain)

            // The one step that changes which file is the database, and it is atomic.
            check(temp.renameTo(plain)) { "could not move the converted database into place" }
            android.util.Log.i(TAG, "Converted $databaseName to an encrypted database")
            true
        }.getOrElse {
            android.util.Log.e(TAG, "Could not convert $databaseName; leaving it as it was", it)
            cleanUp(temp)
            false
        }
    }

    /** Adopts a database stranded by builds <=0.3.2, which deleted the plaintext before renaming. */
    private fun recoverInterrupted(plain: File, temp: File, passphrase: String): Boolean {
        if (plain.exists() || !temp.exists()) return false
        if (!sqlCipherLoaded) return false

        // Only adopt a file this device can actually read. A temp written under a passphrase that
        // has since been destroyed is unrecoverable, and renaming it into place would replace a
        // recoverable empty state with an unopenable one.
        if (versionUnder(temp, passphrase) == null) {
            android.util.Log.e(TAG, "Orphaned ${temp.name} does not open under the current key; discarding it")
            cleanUp(temp)
            return false
        }
        if (!temp.renameTo(plain)) {
            android.util.Log.e(TAG, "Could not adopt orphaned ${temp.name}")
            return false
        }
        android.util.Log.i(TAG, "Recovered ${plain.name} from an interrupted conversion")
        return true
    }

    private fun exportToTemp(plain: File, temp: File, passphrase: String): Int {
        // Opened with NO key: this is still a plaintext file. CREATE_IF_NECESSARY is not about the
        // source, which exists — SQLite only creates the ATTACHed file if the attaching connection
        // was opened with permission to create.
        val source = SQLiteDatabase.openDatabase(
            plain.absolutePath,
            null,
            SQLiteDatabase.OPEN_READWRITE or SQLiteDatabase.CREATE_IF_NECESSARY,
        )
        try {
            val userVersion = source.version
            // ATTACH/sqlcipher_export need rawExecSQL. The key is BOUND, never interpolated.
            source.rawExecSQL("ATTACH DATABASE ? AS encrypted KEY ?", temp.absolutePath, passphrase)
            source.rawExecSQL("SELECT sqlcipher_export('encrypted')")
            // sqlcipher_export copies schema and rows but NOT user_version, which Room reads to
            // decide whether to run migrations.
            source.rawExecSQL("PRAGMA encrypted.user_version = $userVersion")
            source.rawExecSQL("DETACH DATABASE encrypted")
            return userVersion
        } finally {
            source.close()
        }
    }

    private fun versionUnder(file: File, passphrase: String): Int? = runCatching {
        val db = SQLiteDatabase.openDatabase(
            file.absolutePath,
            passphrase.toByteArray(Charsets.UTF_8),
            null,
            SQLiteDatabase.OPEN_READONLY,
            null,
        )
        try {
            db.version
        } finally {
            db.close()
        }
    }.getOrNull()

    /** SQLCipher encrypts the 16-byte header too, so a missing magic means already-converted. */
    fun isPlaintext(file: File): Boolean {
        val header = ByteArray(SQLITE_MAGIC.size)
        // Looped, not a single read(): `InputStream.read` may return fewer bytes than asked for,
        // and the discarded count left the tail zeroed — so a plaintext database read as encrypted.
        // `readNBytes` would say this in one line but is API 33; this app's minSdk is 31.
        val read = file.inputStream().use { stream ->
            var filled = 0
            while (filled < header.size) {
                val count = stream.read(header, filled, header.size - filled)
                if (count < 0) break
                filled += count
            }
            filled
        }
        // A file too short to hold the header is not a database this code should be reasoning
        // about; treat it as not-plaintext and let the open path report it.
        if (read < header.size) return false
        return header.contentEquals(SQLITE_MAGIC)
    }

    private fun deleteJournals(database: File) {
        File(database.parentFile, "${database.name}-wal").delete()
        File(database.parentFile, "${database.name}-shm").delete()
    }

    private fun cleanUp(temp: File) {
        temp.delete()
        deleteJournals(temp)
    }
}
