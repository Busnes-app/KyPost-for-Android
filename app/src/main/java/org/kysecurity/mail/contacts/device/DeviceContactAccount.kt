package org.kysecurity.mail.contacts.device

import android.accounts.Account
import android.accounts.AccountManager
import android.content.ContentValues
import android.content.Context
import android.provider.ContactsContract
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

private const val TAG = "DeviceContactAccount"

object DeviceContactAccount {
    val ACCOUNT_TYPE = "${org.kysecurity.mail.BuildConfig.APPLICATION_ID}.contacts"
    const val ACCOUNT_NAME = "KyPost"

    fun account(): Account = Account(ACCOUNT_NAME, ACCOUNT_TYPE)

    /**
     * CP2 hides a raw contact that belongs to no group unless its account opts in here, so every
     * ungrouped contact we pushed was stored correctly and shown nowhere. Grouped contacts stayed
     * visible (DeviceGroupLinker sets GROUP_VISIBLE), which is why this read as a partial sync
     * rather than a display flag. Insert on Settings is an upsert, so calling this repeatedly
     * updates the one row and repairs installs whose account already exists. It writes only when
     * the flag is off: every write notifies the contacts observer, which runs another sync, which
     * called this again.
     */
    /** True when it had to write the setting; false when it was already on and nothing was written. */
    fun makeContactsVisible(context: Context): Boolean {
        val resolver = context.applicationContext.contentResolver
        val visible = resolver.query(
            ContactsContract.Settings.CONTENT_URI,
            arrayOf(ContactsContract.Settings.UNGROUPED_VISIBLE),
            "${ContactsContract.Settings.ACCOUNT_TYPE} = ? AND ${ContactsContract.Settings.ACCOUNT_NAME} = ?",
            arrayOf(ACCOUNT_TYPE, ACCOUNT_NAME),
            null,
        )?.use { it.moveToFirst() && it.getInt(0) == 1 } ?: false
        if (visible) return false
        val values = ContentValues().apply {
            put(ContactsContract.Settings.ACCOUNT_NAME, ACCOUNT_NAME)
            put(ContactsContract.Settings.ACCOUNT_TYPE, ACCOUNT_TYPE)
            put(ContactsContract.Settings.UNGROUPED_VISIBLE, 1)
        }
        resolver.insert(ContactsContract.Settings.CONTENT_URI, values)
        return true
    }
}

class DeviceContactAccountManager(private val context: Context) {
    private val accountManager = AccountManager.get(context)

    /** Needs no permission: getAccountsByType returns accounts this app's own authenticator signs. */
    fun accountExists(): Boolean = runCatching {
        accountManager.getAccountsByType(DeviceContactAccount.ACCOUNT_TYPE)
            .any { it.name == DeviceContactAccount.ACCOUNT_NAME }
    }.onFailure { Log.e(TAG, "Could not enumerate this app's sync accounts", it) }
        .getOrDefault(false)

    /** Blocking AccountManager IPC — `suspend` alone would not move it off the caller's thread. */
    suspend fun ensureAccount(): Boolean = withContext(Dispatchers.IO) {
        if (accountExists()) return@withContext true
        try {
            accountManager.addAccountExplicitly(DeviceContactAccount.account(), null, null)
        } catch (e: kotlinx.coroutines.CancellationException) {
            throw e
        } catch (e: Exception) {
            // Logged, not swallowed: the caller gates "sync is enabled" on this answer, and a
            // silent false enabled a periodic worker with no account to write under.
            Log.e(TAG, "Could not create the contacts sync account", e)
            false
        }
    }

    suspend fun removeAccount(): Boolean =
        withContext(Dispatchers.IO) { removeAccountBlocking() }

    /** Removing the account is what makes CP2 hard-delete its raw contacts; false must reach callers. */
    fun removeAccountBlocking(): Boolean {
        return try {
            accountManager.removeAccountExplicitly(DeviceContactAccount.account())
        } catch (e: Exception) {
            Log.e(TAG, "Could not remove the contacts sync account", e)
            false
        }
    }
}
