package org.kysecurity.mail.data

import android.content.Context
import androidx.room.Room
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.security.DatabaseKey
import org.kysecurity.mail.security.HostileLocationSettings

class DataGraph(context: Context) : org.kysecurity.mail.ClosableGraph {
    private val appContext = context.applicationContext

    // In-memory under Hostile Location Protection; decided once, so toggling it needs a relaunch.
    val database: AppDatabase = if (HostileLocationSettings(appContext).isEnabled()) {
        Room.inMemoryDatabaseBuilder(appContext, AppDatabase::class.java).build()
    } else {
        Room.databaseBuilder(appContext, AppDatabase::class.java, DATABASE_NAME)
            .openHelperFactory(encryptedOpenHelperFactory(appContext))
            .addMigrations(
                AppDatabase.MIGRATION_1_2,
                AppDatabase.MIGRATION_2_3,
                AppDatabase.MIGRATION_3_4,
                AppDatabase.MIGRATION_4_5,
                AppDatabase.MIGRATION_5_6,
                AppDatabase.MIGRATION_6_7,
                AppDatabase.MIGRATION_7_8,
                AppDatabase.MIGRATION_8_9,
                AppDatabase.MIGRATION_9_10,
                AppDatabase.MIGRATION_10_11,
                AppDatabase.MIGRATION_11_12,
                AppDatabase.MIGRATION_12_13,
            )
            .build()
    }

    /** Converts an existing plaintext file before Room opens it. See [DatabaseMigration]. */
    private fun encryptedOpenHelperFactory(appContext: Context): SupportOpenHelperFactory {
        if (!sqlCipherLoaded) throw DatabaseUnavailableException("libsqlcipher.so could not be loaded")
        // The framework's SQLiteOpenHelper creates `databases/` on demand; SQLCipher's does not,
        // and on a fresh install nothing else has created it.
        appContext.getDatabasePath(DATABASE_NAME).parentFile?.mkdirs()
        val passphrase = DatabaseKey.passphrase(appContext)
        if (!DatabaseMigration.encryptIfNeeded(appContext, DATABASE_NAME, passphrase)) {
            throw DatabaseUnavailableException("$DATABASE_NAME could not be converted to an encrypted database")
        }
        // A fresh array each time: SupportOpenHelperFactory zeroes the one it is given once the
        // database is open.
        return SupportOpenHelperFactory(passphrase.toByteArray(Charsets.UTF_8))
    }

    // AppRestart does not kill the process, so an unclosed in-memory database keeps every body.
    override fun closeGraph() {
        if (database.isOpen) database.close()
    }
}

const val DATABASE_NAME = "kypost_mail.db"

class DatabaseUnavailableException(message: String) : IllegalStateException(message)

object DataRuntime {
    private val holder = SingletonGraph(::DataGraph)

    fun graph(context: Context): DataGraph = holder.get(context)

    fun invalidate() = holder.invalidate()

    /** Takes the instance actually in use, not a freshly built stand-in. */
    fun takeGraph(): DataGraph? = holder.take()

    /** Never resurrects a database that SecurityWipe has already closed and deleted. */
    fun peekGraph(): DataGraph? = holder.peek()
}
