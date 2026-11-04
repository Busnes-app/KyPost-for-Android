package org.kysecurity.mail.contacts.device

import android.content.Context
import android.content.SharedPreferences
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

// Every write is commit(), never apply(): SecurityWipe deletes this file, and apply() resurrects it.
class DeviceContactSyncSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    /** On only with the disclosure agreed to: installs that enabled sync before it named the
     *  server read as off until the user agrees. */
    fun isEnabled(): Boolean = prefs.getBoolean(KEY_ENABLED, false) && consentedDestination() != null

    /** The pairing (`ContactSyncRepository.destination`) whose server the user agreed, on the
     *  disclosure, to send this phone's contacts to. Null until they agree and after they revoke;
     *  replacing the pairing purges through [clearConsentDuring], which clears it. */
    fun consentedDestination(): String? = prefs.getString(KEY_SYNC_CONSENT, null)

    fun recordConsent(destination: String) {
        prefs.edit().putString(KEY_SYNC_CONSENT, destination).commit()
    }

    fun setEnabled(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_ENABLED, enabled).commit()
    }

    /** Calls [onChange] on the main thread after every write, from any instance or thread, until
     *  the returned handle is closed. SharedPreferences holds listeners weakly; the handle keeps
     *  this one alive. */
    fun observe(onChange: () -> Unit): AutoCloseable {
        val listener = SharedPreferences.OnSharedPreferenceChangeListener { _, _ -> onChange() }
        prefs.registerOnSharedPreferenceChangeListener(listener)
        return AutoCloseable { prefs.unregisterOnSharedPreferenceChangeListener(listener) }
    }

    /** One-time repair of title-only merge bases written before `organizationRowOf` (see
     *  [DeviceContactRepository]); true once every link has been checked. */
    fun titleBasesRepaired(): Boolean = prefs.getBoolean(KEY_TITLE_BASES_REPAIRED, false)

    fun markTitleBasesRepaired() {
        prefs.edit().putBoolean(KEY_TITLE_BASES_REPAIRED, true).commit()
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

    /** Bumped by every consent change. Read it before [importAccounts]: a change landing between
     *  the two then reads as a change, never as the old revision. */
    fun consentRevision(): Long = prefs.getLong(KEY_CONSENT_REVISION, 0L)

    /** A newly added account rewinds the scan, or its existing contacts sit behind the watermark.
     *  Waits for an import in progress under [whileConsented], so none starts after this returns. */
    suspend fun setImportAccounts(destination: String, keys: Set<String>) = consentLock.withLock {
        val added = !importAccounts(destination).containsAll(keys)
        val edit = prefs.edit()
            .putString(KEY_IMPORT_DESTINATION, destination)
            .putStringSet(KEY_IMPORT_ACCOUNTS, keys.toSet())
            .putLong(KEY_CONSENT_REVISION, consentRevision() + 1)
        if (added) edit.putLong(KEY_LAST_FOREIGN_SCAN, 0L)
        edit.commit()
        Unit
    }

    /** Moves the watermark to [epochMs] unless consent changed since [revision]: a scan that ran
     *  under older consent must not step over a rewind made while it ran. */
    suspend fun advanceScanWatermark(revision: Long, epochMs: Long) = consentLock.withLock {
        if (consentRevision() == revision) prefs.edit().putLong(KEY_LAST_FOREIGN_SCAN, epochMs).commit()
        Unit
    }

    /** Clears sync and import consent, turns device sync off and runs [block] under the consent lock, for
     *  the account purge: an import or create is either queued before [block] (which then removes
     *  it) or finds no consent and sync off after. */
    suspend fun <T> clearConsentDuring(block: suspend () -> T): T = consentLock.withLock {
        prefs.edit().remove(KEY_IMPORT_ACCOUNTS).remove(KEY_IMPORT_DESTINATION).remove(KEY_SYNC_CONSENT)
            .putLong(KEY_CONSENT_REVISION, consentRevision() + 1)
            .putBoolean(KEY_ENABLED, false).commit()
        block()
    }

    /** Runs [block] only while [accountKey] is consented for [destination], holding the consent
     *  lock so a change cannot land between the check and the write. Null when not consented. */
    suspend fun <T> whileConsented(destination: String, accountKey: String, block: suspend () -> T): T? =
        consentLock.withLock { if (accountKey in importAccounts(destination)) block() else null }

    /** Runs [block] under the lock the account purge holds through [clearConsentDuring]. */
    suspend fun <T> withPurgeLock(block: suspend () -> T): T = consentLock.withLock { block() }

    companion object {
        private const val PREFS_NAME = "org.kysecurity.mail.device_contacts"
        private const val KEY_ENABLED = "enabled"
        private const val KEY_TITLE_BASES_REPAIRED = "title_bases_repaired"
        private const val KEY_LAST_FOREIGN_SCAN = "last_foreign_scan_epoch_ms"
        private const val KEY_SYNC_CONSENT = "sync_consent_destination"
        private const val KEY_IMPORT_ACCOUNTS = "import_account_keys"
        private const val KEY_IMPORT_DESTINATION = "import_destination"
        private const val KEY_CONSENT_REVISION = "import_consent_revision"

        /** Process-wide: every settings instance reads the same preference file. */
        private val consentLock = Mutex()
    }
}

/** Another account's contact storage. Null type and name is the phone's account-less storage. */
data class DeviceAccount(val type: String?, val name: String?) {
    val key: String get() = "${type.orEmpty()}\n${name.orEmpty()}"
}
