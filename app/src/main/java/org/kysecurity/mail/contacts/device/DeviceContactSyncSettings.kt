package org.kysecurity.mail.contacts.device

import android.content.Context
import android.content.SharedPreferences

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

    /** [DeviceAccount.key]s whose contacts the user chose to upload. Empty by default; a new
     *  key rather than a reused one, so installs that imported everything start with none. */
    fun importAccounts(): Set<String> = prefs.getStringSet(KEY_IMPORT_ACCOUNTS, null).orEmpty().toSet()

    /** A newly added account rewinds the scan, or its existing contacts sit behind the watermark. */
    fun setImportAccounts(keys: Set<String>) {
        val edit = prefs.edit().putStringSet(KEY_IMPORT_ACCOUNTS, keys.toSet())
        if (!importAccounts().containsAll(keys)) edit.putLong(KEY_LAST_FOREIGN_SCAN, 0L)
        edit.commit()
    }

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
    }
}

/** Another account's contact storage. Null type and name is the phone's account-less storage. */
data class DeviceAccount(val type: String?, val name: String?) {
    val key: String get() = "${type.orEmpty()}\n${name.orEmpty()}"
}
