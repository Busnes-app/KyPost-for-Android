package org.kysecurity.mail.contacts.device

import android.accounts.AbstractAccountAuthenticator
import android.accounts.Account
import android.accounts.AccountAuthenticatorResponse
import android.app.Service
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.IBinder

/** The authenticator behind [ACCOUNT_TYPE], so test accounts of that type are real accounts the
 *  contacts provider keeps rows for. The app adds them with `addAccountExplicitly`, which
 *  AccountManager allows because this test APK is signed with the app's key. Nothing here is
 *  ever asked to sign anyone in. */
class TestAccountAuthenticatorService : Service() {
    private lateinit var authenticator: Authenticator

    override fun onCreate() {
        super.onCreate()
        authenticator = Authenticator(this)
    }

    override fun onBind(intent: Intent?): IBinder = authenticator.iBinder

    private class Authenticator(context: Context) : AbstractAccountAuthenticator(context) {
        override fun editProperties(response: AccountAuthenticatorResponse?, accountType: String?) = Bundle()
        override fun addAccount(
            response: AccountAuthenticatorResponse?, accountType: String?, authTokenType: String?,
            requiredFeatures: Array<out String>?, options: Bundle?,
        ): Bundle? = null
        override fun confirmCredentials(response: AccountAuthenticatorResponse?, account: Account?, options: Bundle?): Bundle? = null
        override fun getAuthToken(
            response: AccountAuthenticatorResponse?, account: Account?, authTokenType: String?, options: Bundle?,
        ): Bundle? = null
        override fun getAuthTokenLabel(authTokenType: String?): String? = null
        override fun updateCredentials(
            response: AccountAuthenticatorResponse?, account: Account?, authTokenType: String?, options: Bundle?,
        ): Bundle? = null
        override fun hasFeatures(response: AccountAuthenticatorResponse?, account: Account?, features: Array<out String>?): Bundle? = null
    }

    companion object {
        /** Must match `res/xml/test_account_authenticator.xml`. */
        const val ACCOUNT_TYPE = "org.kysecurity.mail.test.importprobe"
    }
}
