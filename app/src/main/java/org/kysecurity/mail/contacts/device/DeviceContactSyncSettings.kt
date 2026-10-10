package org.kysecurity.mail.contacts.device

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// Every write is commit(), never apply(): SecurityWipe deletes this file, and apply() resurrects it.
class DeviceContactSyncSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false)

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }

    fun lastForeignScanAtEpochMs(): Long = prefs.getLong(KEY_LAST_FOREIGN_SCAN, 0L)

    fun setLastForeignScanAtEpochMs(epochMs: Long) {
        prefs.edit().putLong(KEY_LAST_FOREIGN_SCAN, epochMs).commit()
    }

    /** [DeviceAccount.key]s whose contacts the user chose to upload to [destination], the
     *  pairing they were chosen under (`ContactSyncRepository.destination`). Empty by default and
     *  for any other destination; a new key rather than a reused one, so installs that imported
     *  everything start with none. */
    fun importAccounts(destination: String): Set<String> =
        if (prefs.getString(KEY_IMPORT_DESTINATION, null) == destination) {
            prefs.getStringSet(KEY_IMPORT_ACCOUNTS, null).orEmpty().toSet()
        } else {
            emptySet()
        }

    /** A newly added account rewinds the scan, or its existing contacts sit behind the watermark.
     *  Waits for an import in progress under [whileConsented], so none starts after this returns. */
    suspend fun setImportAccounts(destination: String, keys: Set<String>) = consentLock.withLock {
        val added = !importAccounts(destination).containsAll(keys)
        val edit = prefs.edit()
            .putString(KEY_IMPORT_DESTINATION, destination)
            .putStringSet(KEY_IMPORT_ACCOUNTS, keys.toSet())
        if (added) edit.putLong(KEY_LAST_FOREIGN_SCAN, 0L)
        edit.commit()
        Unit
    }

    /** Runs [block] only while [accountKey] is consented for [destination], holding the consent
     *  lock so a change cannot land between the check and the write. Null when not consented. */
    suspend fun <T> whileConsented(destination: String, accountKey: String, block: suspend () -> T): T? =
        consentLock.withLock { if (accountKey in importAccounts(destination)) block() else null }

    fun hasShownSyncIntro(): Boolean = prefs.getBoolean(KEY_SHOWN_INTRO, false)

    fun setHasShownSyncIntro(shown: Boolean) {
        prefs.edit().putBoolean(KEY_SHOWN_INTRO, shown).commit()
    }

    companion object {
        private const val PREFS_NAME = "org.kysecurity.mail.device_contacts"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_LAST_FOREIGN_SCAN = "last_foreign_scan_epoch_ms"
        private const val KEY_SHOWN_INTRO = "has_shown_sync_intro"
        private const val KEY_IMPORT_ACCOUNTS = "import_account_keys"
        private const val KEY_IMPORT_DESTINATION = "import_destination"

        /** Process-wide: every settings instance reads the same preference file. */
        private val consentLock = Mutex()
    }
}

/** Another account's contact storage. Null type and name is the phone's account-less storage. */
data class DeviceAccount(val type: String?, val name: String?) {
    val key: String get() = "${type.orEmpty()}\n${name.orEmpty()}"
}
