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
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.push.PushPairingActivity
import org.kysecurity.mail.push.pairingDeepLink
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

    private val chooseAccount = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val account = if (result.resultCode == RESULT_OK) accountFrom(result.data?.extras) else null
        val (server, config) = pending ?: return@registerForActivityResult
        if (account != null) requestToken(account, server, config) else setWorking(false)
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
        val server = serverField.text.toString().trim()
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
        chooseAccount.launch(
            AccountManager.newChooseAccountIntent(null, null, arrayOf(AuthenticatorPin.ACCOUNT_TYPE), null, null, null, null),
        )
    }

    private fun requestToken(account: Account, server: String, config: SignOnConfig) {
        val am = AccountManager.get(this)
        val issuer = am.getUserData(account, "server_url")?.trimEnd('/')
        if (canonicalOrigin(issuer) != canonicalOrigin(config.issuerUrl)) {
            status.text = getString(
                R.string.kyidentity_signon_issuer_mismatch,
                hostOf(config.issuerUrl),
                issuer?.let(::hostOf) ?: getString(R.string.kyidentity_signon_other_server),
            )
            setWorking(false)
            return
        }
        lifecycleScope.launch {
            val token = withContext(Dispatchers.IO) {
                runCatching {
                    am.getAuthToken(account, config.clientId, null, this@KyIdentitySignOnActivity, null, null)
                        .result.getString(AccountManager.KEY_AUTHTOKEN)
                }
            }
            token.onFailure { e ->
                setWorking(false)
                when (e) {
                    is OperationCanceledException -> Unit
                    is AuthenticatorException -> status.text = e.message?.lineSequence()?.first()?.take(200)?.ifBlank { null } ?: getString(R.string.kyidentity_signon_refused)
                    else -> status.text = getString(R.string.kyidentity_signon_token_failed)
                }
            }.onSuccess { idToken ->
                if (idToken.isNullOrBlank()) {
                    status.setText(R.string.kyidentity_signon_no_token)
                    setWorking(false)
                } else {
                    exchange(server, idToken)
                }
            }
        }
    }

    private suspend fun exchange(server: String, idToken: String) {
        val result = KyIdentitySignOnClient(pairingHttpClient(PinPosture.TofuWindow, 15_000))
            .signOn(server, idToken)
        setWorking(false)
        when (result) {
            is PairingParseResult.Error -> Toast.makeText(this, result.reason, Toast.LENGTH_LONG).show()
            is PairingParseResult.Success -> {
                startActivity(Intent(this, PushPairingActivity::class.java).apply {
                    addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP)
                    data = android.net.Uri.parse(pairingDeepLink(result.pairing))
                })
                finish()
            }
        }
    }

    /** scheme://host:port/path, normalised by OkHttp; null when it is not an http(s) URL. */
    private fun canonicalOrigin(url: String?): String? =
        url?.toHttpUrlOrNull()?.let { "${it.scheme}://${it.host}:${it.port}${it.encodedPath.trimEnd('/')}" }

    private fun hostOf(url: String): String = android.net.Uri.parse(url).host ?: url
}
