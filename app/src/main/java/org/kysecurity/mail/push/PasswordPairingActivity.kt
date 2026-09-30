package org.kysecurity.mail.push

import android.content.Intent
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.Toast
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.launch
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.security.LockedActivity

class PasswordPairingActivity : LockedActivity() {
    private lateinit var pairButton: Button

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_password_pairing)
        setTitle(R.string.password_pairing_title)
        applyTopInsetWithHeader(this, findViewById(R.id.passwordPairingRoot))
        pairButton = findViewById(R.id.btnPasswordPair)
        pairButton.setOnClickListener { pair() }
        applyThemeToActivity(this)
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, pairButton)
    }

    private fun pair() {
        val server = findViewById<EditText>(R.id.fastPairServer).text.toString()
        val username = findViewById<EditText>(R.id.fastPairUsername).text.toString()
        val password = findViewById<EditText>(R.id.fastPairPassword).text.toString()
        pairButton.isEnabled = false
        lifecycleScope.launch {
            val result = PasswordPairingClient(pairingHttpClient(PinPosture.TofuWindow, 15_000))
                .mint(server, username, password)
            findViewById<EditText>(R.id.fastPairPassword).text.clear()
            pairButton.isEnabled = true
            when (result) {
                is PairingParseResult.Error -> Toast.makeText(this@PasswordPairingActivity, result.reason, Toast.LENGTH_LONG).show()
                is PairingParseResult.Success -> {
                    startActivity(Intent(this@PasswordPairingActivity, PushPairingActivity::class.java).apply {
                        data = android.net.Uri.parse(pairingDeepLink(result.pairing))
                    })
                    finish()
                }
            }
        }
    }
}
