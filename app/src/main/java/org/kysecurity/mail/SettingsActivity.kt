package org.kysecurity.mail

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import com.google.android.material.navigation.NavigationBarView
import org.kysecurity.mail.pgp.PgpKeyActivity
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.SecuritySettingsActivity

class SettingsActivity : LockedActivity() {
    private lateinit var bottomNav: NavigationBarView

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_settings)
        applyTopInsetWithHeader(this, findViewById(R.id.settingsContent))
        bottomNav = findViewById(R.id.bottomNavigation)
        applyPrimaryNavigationInsets(this, bottomNav)
        setupPrimaryNavigation(this, bottomNav, R.id.nav_settings)
        applyTheme()

        findViewById<Button>(R.id.settingsSecurity).setOnClickListener {
            startActivity(Intent(this, SecuritySettingsActivity::class.java))
        }
        findViewById<Button>(R.id.settingsThemes).setOnClickListener {
            startActivity(Intent(this, ThemesActivity::class.java))
        }
        findViewById<Button>(R.id.settingsKeywords).setOnClickListener {
            startActivity(Intent(this, KeywordSettingsActivity::class.java))
        }
        findViewById<Button>(R.id.settingsPairing).setOnClickListener {
            startActivity(Intent(this, org.kysecurity.mail.push.PushPairingActivity::class.java))
        }
        findViewById<Button>(R.id.settingsPgp).setOnClickListener {
            startActivity(Intent(this, PgpKeyActivity::class.java))
        }
        findViewById<Button>(R.id.settingsAbout).setOnClickListener {
            showAboutDialog(this)
        }
        findViewById<Button>(R.id.settingsPrivacy).setOnClickListener {
            startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(getString(R.string.settings_privacy_url))))
        }
        findViewById<Button>(R.id.settingsSupport).setOnClickListener {
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

        val palette = getStoredThemePalette(this)
        listOf(
            R.id.settingsSecurity,
            R.id.settingsThemes,
            R.id.settingsKeywords,
            R.id.settingsPairing,
            R.id.settingsPgp,
            R.id.settingsAbout,
            R.id.settingsPrivacy,
            R.id.settingsSupport,
        ).forEach { applyGhostButtonTheme(this, findViewById<Button>(it)) }
        listOf(
            R.id.settingsSecurityBody,
            R.id.settingsThemesBody,
            R.id.settingsKeywordsBody,
            R.id.settingsPairingBody,
            R.id.settingsPgpBody,
            R.id.settingsAboutBody,
            R.id.settingsPrivacyBody,
            R.id.settingsSupportBody,
        ).forEach { findViewById<TextView>(it).setTextColor(Color.parseColor(palette.ink)) }
    }
}

internal fun supportUrlForFlavor(flavor: String): String? =
    if (flavor == "play") null else "https://buymeacoffee.com/yoshiofthewire"
