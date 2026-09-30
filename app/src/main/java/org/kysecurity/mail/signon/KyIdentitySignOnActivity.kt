package org.kysecurity.mail.signon

import android.accounts.Account
import android.accounts.AccountManager
import android.accounts.AccountManagerFuture
import android.accounts.AuthenticatorException
import android.accounts.OperationCanceledException
import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kysecurity.mail.KyPostApp
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.push.PushPairingActivity
import org.kysecurity.mail.security.LockedActivity

/**
 * Pairs through the KyIdentity account KyAuth publishes: read the relay's SSO config, get an ID
 * token from AccountManager (KyAuth prompts), swap it for a pairing deep link, then hand that link
 * to the ordinary pairing flow so registration, TLS pinning and secret storage stay unchanged.
 * The ID token lives in a local for one call; it is never stored or logged.
 */
class KyIdentitySignOnActivity : LockedActivity() {
    private lateinit var button: Button
    private lateinit var status: TextView
    private lateinit var serverField: EditText
    private var pending: Pair<String, SignOnConfig>? = null
    private var chooserHadNoAccounts = false

    private val chooseAccount = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val account = if (result.resultCode == RESULT_OK) accountFrom(result.data?.extras) else null
        val (server, config) = pending ?: return@registerForActivityResult
        if (account != null) {
            requestToken(account, server, config)
        } else {
            setWorking(false)
            if (chooserHadNoAccounts) status.setText(R.string.kyidentity_signon_no_account)
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_kyidentity_signon)
        setTitle(R.string.kyidentity_signon_title)
        applyTopInsetWithHeader(this, findViewById(R.id.kyIdentitySignOnRoot))
        button = findViewById(R.id.btnKyIdentitySignOn)
        status = findViewById(R.id.kyIdentitySignOnStatus)
        serverField = findViewById(R.id.kyIdentitySignOnServer)
        button.setOnClickListener { start() }
        applyThemeToActivity(this)
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, button)
    }

    private fun accountFrom(extras: Bundle?): Account? {
        val name = extras?.getString(AccountManager.KEY_ACCOUNT_NAME)
        val type = extras?.getString(AccountManager.KEY_ACCOUNT_TYPE)
        return if (name != null && type == AuthenticatorPin.ACCOUNT_TYPE) Account(name, type) else null
    }

    private fun start() {
        if (!AuthenticatorPin.trustedAuthenticator(this)) {
            status.setText(R.string.kyidentity_signon_no_authenticator)
            return
        }
        val server = typedRelayUrl(serverField.text.toString())
        setWorking(true)
        status.text = ""
        lifecycleScope.launch {
            val client = KyIdentitySignOnClient(pairingHttpClient(PinPosture.TofuWindow, 15_000))
            when (val cfg = client.config(server)) {
                is SignOnConfigResult.Unavailable -> { status.text = cfg.reason; setWorking(false) }
                is SignOnConfigResult.Ready -> pickAccount(server, cfg.config)
            }
        }
    }

    private fun setWorking(working: Boolean) {
        button.isEnabled = !working
        serverField.isEnabled = !working
    }

    private fun pickAccount(server: String, config: SignOnConfig) {
        pending = server to config
        val accounts = AccountManager.get(this).getAccountsByType(AuthenticatorPin.ACCOUNT_TYPE)
        if (accounts.size == 1) {
            requestToken(accounts[0], server, config)
            return
        }
        chooserHadNoAccounts = accounts.isEmpty()
        chooseAccount.launch(
            AccountManager.newChooseAccountIntent(null, null, arrayOf(AuthenticatorPin.ACCOUNT_TYPE), null, null, null, null),
        )
    }

    private fun requestToken(account: Account, server: String, config: SignOnConfig) {
        val am = AccountManager.get(this)
        val issuer = am.getUserData(account, "server_url")?.trimEnd('/')
        if (!sameIssuer(issuer, config.issuerUrl)) {
            status.text = getString(
                R.string.kyidentity_signon_issuer_mismatch,
                canonicalOrigin(config.issuerUrl) ?: config.issuerUrl,
                canonicalOrigin(issuer) ?: getString(R.string.kyidentity_signon_other_server),
            )
            setWorking(false)
            return
        }
        // App scope: the app lock may destroy this activity while KyAuth's prompt is up.
        val app = application as KyPostApp
        app.appScope.launch {
            val token = runCatching {
                am.getAuthToken(
                    account, config.clientId, Bundle().apply { putString(KyIdentitySignOn.OPTION_ORIGIN, server) },
                    this@KyIdentitySignOnActivity, null, null,
                )
                    .result.getString(AccountManager.KEY_AUTHTOKEN)
            }
            token.onFailure { e ->
                when (e) {
                    is OperationCanceledException -> finishWorking(null)
                    is AuthenticatorException, is UnsupportedOperationException, is IllegalArgumentException ->
                        finishWorking(e.message?.lineSequence()?.first()?.take(200)?.ifBlank { null }
                            ?: getString(R.string.kyidentity_signon_refused))
                    else -> finishWorking(getString(R.string.kyidentity_signon_token_failed))
                }
            }.onSuccess { idToken ->
                if (idToken.isNullOrBlank()) finishWorking(getString(R.string.kyidentity_signon_no_token))
                else exchange(server, idToken)
            }
        }
    }

    /** Re-enables the UI and shows [message]; a no-op when the app lock already destroyed the activity. */
    private suspend fun finishWorking(message: String?) = withContext(Dispatchers.Main) {
        if (isDestroyed) return@withContext
        setWorking(false)
        if (message != null) status.text = message
    }

    private suspend fun exchange(server: String, idToken: String) {
        val result = KyIdentitySignOnClient(pairingHttpClient(PinPosture.TofuWindow, 15_000))
            .signOn(server, idToken)
        when (result) {
            is PairingParseResult.Error -> finishWorking(result.reason)
            is PairingParseResult.Success -> withContext(Dispatchers.Main) {
                PendingPairingLink.set(result.pairing)
                if (isDestroyed) return@withContext
                startActivity(Intent(this@KyIdentitySignOnActivity, PushPairingActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
                })
                finish()
            }
        }
    }
}
