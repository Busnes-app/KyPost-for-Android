package org.kysecurity.mail.contacts.device

import android.accounts.AbstractAccountAuthenticator
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.content.Intent
import android.os.Bundle

class KyPostContactAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {
    /** No properties to edit. Answered directly: a null return leaves the caller waiting for a
     *  response this method never sends. */
    override fun editProperties(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
    ): Bundle = Bundle()

    /** The account is created by turning device sync on, with its consent prompts, so "Add
     *  account" opens the Contacts screen where that switch lives instead of creating one here.
     *  The caller's request is held in [PendingAccountSetup] and answered with the account once
     *  device sync is on, or cancelled if the user leaves without turning it on. */
    override fun addAccount(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
        authTokenType: String?,
        requiredFeatures: Array<out String>?,
        options: Bundle?,
    ): Bundle? {
        if (DeviceContactAccountManager(context).accountExists()) return accountResult(DeviceContactAccount.ACCOUNT_NAME)
        if (response != null) {
            PendingAccountSetup.hold(
                onAdded = { name -> response.onResult(accountResult(name)) },
                onCancelled = { response.onError(AccountManager.ERROR_CODE_CANCELED, "Device contact sync was not turned on") },
            )
        }
        return Bundle().apply {
            putParcelable(
                AccountManager.KEY_INTENT,
                Intent(context, org.kysecurity.mail.contacts.ContactsListActivity::class.java)
                    .putExtra(org.kysecurity.mail.contacts.ContactsListActivity.EXTRA_ACCOUNT_SETUP, true),
            )
        }
    }

    private fun accountResult(name: String) = Bundle().apply {
        putString(AccountManager.KEY_ACCOUNT_NAME, name)
        putString(AccountManager.KEY_ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
    }

    override fun confirmCredentials(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        options: Bundle?,
    ): Bundle? = null

    override fun getAuthToken(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle = throw UnsupportedOperationException()

    override fun getAuthTokenLabel(authTokenType: String?): String? = null

    override fun updateCredentials(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        authTokenType: String?,
        options: Bundle?,
    ): Bundle? = null

    override fun hasFeatures(
        response: AccountAuthenticatorResponse?,
        account: android.accounts.Account?,
        features: Array<out String>?,
    ): Bundle = Bundle().apply { putBoolean(AccountManager.KEY_BOOLEAN_RESULT, false) }
}
