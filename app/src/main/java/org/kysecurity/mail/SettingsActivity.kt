package org.kysecurity.mail

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import com.google.android.material.navigation.NavigationBarView
import org.kysecurity.mail.pgp.PgpKeyActivity
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.SecuritySettingsActivity

class SettingsActivity : LockedActivity() {
    private lateinit var bottomNav: NavigationBarView

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_settings)
        applyTopInsetWithHeader(this, findViewById(R.id.settingsContent), withActionBar = false)
        bottomNav = findViewById(R.id.bottomNavigation)
        applyPrimaryNavigationInsets(this, bottomNav)
        setupPrimaryNavigation(this, bottomNav, R.id.nav_settings)
        applyTheme()

        findViewById<View>(R.id.settingsSecurity).setOnClickListener {
            startActivity(Intent(this, SecuritySettingsActivity::class.java))
        }
        findViewById<View>(R.id.settingsThemes).setOnClickListener {
            startActivity(Intent(this, ThemesActivity::class.java))
        }
        findViewById<View>(R.id.settingsKeywords).setOnClickListener {
            startActivity(Intent(this, KeywordSettingsActivity::class.java))
        }
        findViewById<View>(R.id.settingsPairing).setOnClickListener {
            startActivity(Intent(this, org.kysecurity.mail.push.PushPairingActivity::class.java))
        }
        findViewById<View>(R.id.settingsPgp).setOnClickListener {
            startActivity(Intent(this, PgpKeyActivity::class.java))
        }
        findViewById<View>(R.id.settingsSignature).setOnClickListener {
            showSignatureDialog(this)
        }
        findViewById<View>(R.id.settingsAbout).setOnClickListener {
            showAboutDialog(this)
        }
        findViewById<View>(R.id.settingsPrivacy).setOnClickListener {
            runCatching {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.settings_privacy_url))))
            }.onFailure {
                Toast.makeText(this, R.string.email_link_no_handler, Toast.LENGTH_SHORT).show()
            }
        }
        findViewById<View>(R.id.settingsSupport).setOnClickListener {
            val supportUrl = supportUrlForFlavor(BuildConfig.FLAVOR)
            if (supportUrl == null) {
                startActivity(Intent().setClassName(this, "$packageName.TipActivity"))
            } else {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(supportUrl)))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyTheme()
    }

    private fun applyTheme() {
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(R.string.settings_subtitle))
        applyPrimaryNavigationTheme(this, bottomNav)

        listOf(
            R.id.settingsSecurity,
            R.id.settingsThemes,
            R.id.settingsKeywords,
            R.id.settingsPairing,
            R.id.settingsPgp,
            R.id.settingsSignature,
            R.id.settingsAbout,
            R.id.settingsPrivacy,
            R.id.settingsSupport,
        ).forEach { applyListRowTheme(this, findViewById<ViewGroup>(it)) }
        applyListDividers(this, findViewById(R.id.settingsContent))
    }
}

internal fun supportUrlForFlavor(flavor: String): String? =
    if (flavor == "play") null else "https://buymeacoffee.com/yoshiofthewire"
