package org.kysecurity.mail.mail

import android.content.Context
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import org.kysecurity.mail.ScopedValue
import kotlinx.coroutines.runBlocking

private val Context.mailSyncDataStore by preferencesDataStore(name = "mail_sync_state")

private const val FULL_RESYNC_INTERVAL_MS = 24L * 60 * 60 * 1000

interface MailCursorProvider {
    /** Null means "no cursor yet for this subscriber+folder" — caller should send since=0. */
    fun cursor(subscriberId: String, folder: String): String?
    fun saveCursor(subscriberId: String, folder: String, cursor: String)
    /** True once a day (per subscriber+folder) or if a full resync has never been recorded —
     *  the documented self-heal for a missed removal notification (docs/Mobile_Mail_Relay.md Part 5). */
    fun shouldForceFullResync(subscriberId: String, folder: String): Boolean
    fun recordFullResync(subscriberId: String, folder: String)
}

// Scoped per subscriber+folder so re-pairing cannot apply a stale cursor; cursors are opaque.
class MailCursorStore(
    private val context: Context,
    private val nowProvider: () -> Long = { System.currentTimeMillis() },
) : MailCursorProvider {

    private val hostileLocationSettings = org.kysecurity.mail.security.HostileLocationSettings(context)

    // Under Hostile Location Protection even these keys would leak the folder taxonomy to disk.
    private val inMemoryCursors = mutableMapOf<String, String>()
    private val inMemoryResyncAt = mutableMapOf<String, Long>()

    private fun inMemory(): Boolean = hostileLocationSettings.isEnabled()

    override fun cursor(subscriberId: String, folder: String): String? {
        if (inMemory()) {
            return synchronized(inMemoryCursors) { inMemoryCursors[memKey(subscriberId, folder)] }
                ?.takeIf { it.isNotBlank() }
        }
        return runBlocking { cursorValue(folder).get(subscriberId)?.takeIf { it.isNotBlank() } }
    }

    override fun saveCursor(subscriberId: String, folder: String, cursor: String) {
        if (cursor.isBlank()) return
        if (inMemory()) {
            synchronized(inMemoryCursors) { inMemoryCursors[memKey(subscriberId, folder)] = cursor }
            return
        }
        runBlocking { cursorValue(folder).set(subscriberId, cursor) }
    }

    override fun shouldForceFullResync(subscriberId: String, folder: String): Boolean {
        val lastAt = if (inMemory()) {
            synchronized(inMemoryResyncAt) { inMemoryResyncAt[memKey(subscriberId, folder)] }
        } else {
            runBlocking { resyncValue(folder).get(subscriberId) }
        }
        return lastAt == null || (nowProvider() - lastAt) >= FULL_RESYNC_INTERVAL_MS
    }

    override fun recordFullResync(subscriberId: String, folder: String) {
        if (inMemory()) {
            synchronized(inMemoryResyncAt) { inMemoryResyncAt[memKey(subscriberId, folder)] = nowProvider() }
            return
        }
        runBlocking { resyncValue(folder).set(subscriberId, nowProvider()) }
    }

    private fun memKey(subscriberId: String, folder: String) = "$subscriberId\u0000$folder"

    private fun cursorValue(folder: String) = ScopedValue(
        dataStore = context.mailSyncDataStore,
        scopeKey = stringPreferencesKey("inbox_cursor_scope_${folderKey(folder)}"),
        valueKey = stringPreferencesKey("inbox_cursor_value_${folderKey(folder)}"),
    )

    /** Its own scope key: sharing the cursor's would re-stamp and re-authorise a stale cursor. */
    private fun resyncValue(folder: String) = ScopedValue(
        dataStore = context.mailSyncDataStore,
        scopeKey = stringPreferencesKey("inbox_resync_scope_${folderKey(folder)}"),
        valueKey = longPreferencesKey("inbox_last_full_resync_${folderKey(folder)}"),
    )

    private companion object {
        /** Hashed so key names cannot spell out the folder taxonomy. Changing it costs one resync. */
        private fun folderKey(folder: String): String {
            val digest = java.security.MessageDigest.getInstance("SHA-256")
                .digest(folder.toByteArray(Charsets.UTF_8))
            return digest.take(12).joinToString("") { "%02x".format(it) }
        }
    }
}
