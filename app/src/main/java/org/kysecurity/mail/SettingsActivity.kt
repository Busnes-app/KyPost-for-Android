package org.kysecurity.mail

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.navigation.NavigationBarView
import kotlinx.coroutines.launch
import org.kysecurity.mail.contacts.device.DeviceContactSyncEnabler
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.pgp.PgpKeyActivity
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.SecuritySettingsActivity

class SettingsActivity : LockedActivity() {
    private lateinit var bottomNav: NavigationBarView
    private val contactPermissionLauncher: ActivityResultLauncher<Array<String>> = registerForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) { permissions ->
        if (permissions.all { it.value }) {
            syncEnabler.enableAfterPermissionGrant()
        } else {
            Toast.makeText(this, R.string.contacts_device_sync_permission_denied, Toast.LENGTH_SHORT).show()
        }
    }
    private val syncEnabler: DeviceContactSyncEnabler = DeviceContactSyncEnabler(this, contactPermissionLauncher)

    /** The contact-sync disclosure or the revoke confirmation, while shown. */
    @androidx.annotation.VisibleForTesting
    internal var contactSyncDialog: AlertDialog? = null

    /** The row follows the setting itself, not a callback: revoke and agree finish after their
     *  dialog closes, and a pairing change elsewhere clears the consent too. */
    private var contactSyncObserver: AutoCloseable? = null

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
        findViewById<View>(R.id.settingsContactSync).setOnClickListener { onContactSyncClicked() }
        findViewById<View>(R.id.settingsPgp).setOnClickListener {
            startActivity(Intent(this, PgpKeyActivity::class.java))
        }
        findViewById<View>(R.id.settingsSignature).setOnClickListener {
            startActivity(Intent(this, SignatureSettingsActivity::class.java))
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
        contactSyncObserver = contactSyncObserver ?: DeviceContactsRuntime.graph(this).settings.observe(::renderContactSync)
        renderContactSync()
    }

    override fun onPause() {
        contactSyncObserver?.close()
        contactSyncObserver = null
        super.onPause()
    }

    override fun onDestroy() {
        contactSyncDialog?.dismiss()
        contactSyncDialog = null
        super.onDestroy()
    }

    /** Contacts leave the phone only with the disclosure agreed to; this row gives and withdraws
     *  that consent, naming the server either way. */
    private fun renderContactSync() {
        val destination = DeviceContactsRuntime.graph(this).settings.takeIf { it.isEnabled() }?.consentedDestination()
        findViewById<TextView>(R.id.settingsContactSyncBody).text = destination
            ?.let { getString(R.string.settings_contact_sync_on_body, it.substringBefore('\n')) }
            ?: getString(R.string.settings_contact_sync_off_body)
    }

    private fun onContactSyncClicked() {
        val settings = DeviceContactsRuntime.graph(this).settings
        val consented = settings.consentedDestination()
        if (settings.isEnabled() && consented != null) {
            contactSyncDialog = AlertDialog.Builder(this)
                .setTitle(R.string.settings_contact_sync_revoke_title)
                .setMessage(getString(R.string.settings_contact_sync_revoke_message, consented.substringBefore('\n')))
                .setPositiveButton(R.string.settings_contact_sync_revoke_positive) { _, _ -> syncEnabler.revoke() }
                .setNegativeButton(R.string.cancel, null)
                .showThemed()
            return
        }
        lifecycleScope.launch {
            val destination = syncEnabler.pairedDestination() ?: return@launch
            contactSyncDialog = syncEnabler.askToEnable(destination)
        }
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
            R.id.settingsContactSync,
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
