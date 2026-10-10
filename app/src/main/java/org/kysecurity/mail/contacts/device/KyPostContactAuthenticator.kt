package org.kysecurity.mail.contacts.device

import android.accounts.AbstractAccountAuthenticator
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Context
import android.content.Intent
import android.os.Bundle

class KyPostContactAuthenticator(private val context: Context) : AbstractAccountAuthenticator(context) {
    /** No properties to edit. */
    override fun editProperties(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
    ): Bundle? = null

    /** The account is created by turning device sync on, with its consent prompts, so "Add
     *  account" opens the Contacts screen where that switch lives instead of creating one here. */
    override fun addAccount(
        response: AccountAuthenticatorResponse?,
        accountType: String?,
        authTokenType: String?,
        requiredFeatures: Array<out String>?,
        options: Bundle?,
    ): Bundle = Bundle().apply {
        putParcelable(
            AccountManager.KEY_INTENT,
            Intent(context, org.kysecurity.mail.contacts.ContactsListActivity::class.java),
        )
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
