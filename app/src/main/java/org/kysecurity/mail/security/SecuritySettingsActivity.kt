package org.kysecurity.mail.security

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.widget.SwitchCompat
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import org.kysecurity.mail.addViewSpaced
import org.kysecurity.mail.applyDangerButtonTheme
import org.kysecurity.mail.applyGhostButtonTheme
import org.kysecurity.mail.applyPanelBackground
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applySectionEyebrowLabel
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.applyWarningCalloutTheme
import org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.dpToPx
import org.kysecurity.mail.getStoredThemePalette
import org.kysecurity.mail.pgp.AndroidIdentitySource
import org.kysecurity.mail.pgp.DeviceEnrollmentActivity
import org.kysecurity.mail.pgp.EnrollmentRow
import org.kysecurity.mail.pgp.EnrollmentSession
import org.kysecurity.mail.pgp.EnrollmentStatus
import org.kysecurity.mail.pgp.EnrollmentTeardown
import org.kysecurity.mail.pgp.EnrollmentVault
import org.kysecurity.mail.pgp.IdentityCheck
import org.kysecurity.mail.pgp.enrollmentRowFor
import org.kysecurity.mail.pgp.hasSecureLockScreen
import org.kysecurity.mail.pgp.openWebmail
import org.kysecurity.mail.pgp.isEnrolled
import org.kysecurity.mail.pgp.probeEnrollment
import org.kysecurity.mail.pgp.webmailHomeUrl
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

private val SecurityWork = Dispatchers.Default + NonCancellable

/** Top-level so the instrumented test drives the same code the toggle does. */
internal fun tearDownEnrollmentForHostileLocation(context: android.content.Context) {
    val leftBehind = org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(context)
    if (leftBehind.isNotEmpty()) {
        android.util.Log.e(
            "SecuritySettings",
            "Enrollment teardown left $leftBehind behind while enabling protection",
        )
    }
    org.kysecurity.mail.pgp.EnrollmentStateWorker.enqueue(context)
}

/** Toggles 2 and 3 are disabled unless toggle 1 is on; enforced here, not just documented. */
class SecuritySettingsActivity : LockedActivity() {

    private lateinit var appLockStore: AppLockStore
    private lateinit var lockSwitch: SwitchCompat
    private lateinit var changePinButton: Button
    private lateinit var lockGraceButton: Button
    private lateinit var wipeThresholdButton: Button
    private lateinit var biometricSwitch: SwitchCompat
    private lateinit var hostileLocationSwitch: SwitchCompat
    private lateinit var hostileLocationIntro: TextView
    private lateinit var credentialGateSwitch: SwitchCompat
    private lateinit var encryptionSectionLabel: TextView
    private lateinit var encryptionCard: LinearLayout

    /** Cards awaiting their rounded panel fill, which can only be applied after
     *  `applyThemeToActivity` has finished flattening every ViewGroup. */
    private val panelCards = mutableListOf<LinearLayout>()
    private lateinit var encryptionRowText: TextView
    private lateinit var encryptionActionButton: Button
    private var suppressLockToggleListener = false
    private var suppressCredentialGateListener = false
    private var suppressHostileLocationListener = false

    /** Read once, off the main thread: most of these come from the Keystore-backed store. */
    private data class SettingsSnapshot(
        val lockEnabled: Boolean,
        val biometricEnabled: Boolean,
        val credentialGateEnabled: Boolean,
        val hostileLocationEnabled: Boolean,
        val graceMillis: Long,
        val wipeAfterAttempts: Int?,

        /** Where the PIN pepper lives. Not a diagnostic: it is the difference between the PIN
         *  costing years to guess and costing an afternoon. See [PepperSecurityLevel]. */
        val pinPepperLevel: PepperSecurityLevel,
    )

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        appLockStore = SecurityRuntime.graph(this).appLockStore
        setTitle(R.string.security_settings_title)

        lifecycleScope.launch {
            val graph = SecurityRuntime.graph(this@SecuritySettingsActivity)
            val snapshot = withContext(SecurityWork) {
                SettingsSnapshot(
                    lockEnabled = appLockStore.isLockEnabled(),
                    biometricEnabled = appLockStore.isBiometricEnabled(),
                    credentialGateEnabled = appLockStore.isCredentialPinGateEnabled(),
                    hostileLocationEnabled = graph.hostileLocationSettings.isEnabled(),
                    graceMillis = graph.appLockSettings.graceMillis(),
                    wipeAfterAttempts = graph.appLockStore.wipeAfterAttempts(),
                    // Keystore I/O, so it belongs in this off-main block with the rest.
                    pinPepperLevel = pinPepperSecurityLevel(),
                )
            }
            if (isFinishing || isDestroyed) return@launch
            buildViews(snapshot)
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        // ::isInitialized guards the window between onCreate's launch starting and buildViews
        // running — onResume can fire first, and these are lateinit.
        if (::encryptionRowText.isInitialized) refreshEncryptionRow()
    }

    private fun buildViews(snapshot: SettingsSnapshot) {
        val scrollView = ScrollView(this)
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(16), dpToPx(12), dpToPx(16), dpToPx(20))
        }
        applyTopInsetWithHeader(this, scrollView)

        val lockCard = container.addSection(R.string.security_section_app_lock)

        lockSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_require_unlock_title)
            isChecked = snapshot.lockEnabled
        }
        lockCard.addViewSpaced(lockSwitch, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_require_unlock_intro)), bottomDp = 10)

        changePinButton = Button(this).apply {
            text = getString(R.string.security_change_pin_button)
            visibility = if (snapshot.lockEnabled) View.VISIBLE else View.GONE
            setOnClickListener { promptChangePin() }
        }
        biometricSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_use_biometric_title)
            isChecked = snapshot.biometricEnabled
            isEnabled = snapshot.lockEnabled
        }
        lockCard.addViewSpaced(biometricSwitch, bottomDp = 10)

        val lockGraceSettings = SecurityRuntime.graph(this).appLockSettings
        lockGraceButton = Button(this).apply {
            text = lockGraceButtonLabel(snapshot.graceMillis)
            isEnabled = snapshot.lockEnabled
            setOnClickListener { promptLockGrace(lockGraceSettings) }
        }
        val secondaryActions = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
        secondaryActions.addView(
            changePinButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                .apply { marginEnd = dpToPx(8) },
        )
        secondaryActions.addView(
            lockGraceButton,
            LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f),
        )
        lockCard.addViewSpaced(secondaryActions, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_lock_grace_intro)), bottomDp = 8)

        wipeThresholdButton = Button(this).apply {
            text = wipeThresholdButtonLabel(snapshot.wipeAfterAttempts)
            isEnabled = snapshot.lockEnabled
            setOnClickListener { promptWipeThreshold() }
        }
        lockCard.addViewSpaced(wipeThresholdButton, bottomDp = 4)
        lockCard.addViewSpaced(caption(getString(R.string.security_wipe_threshold_intro)), bottomDp = 0)

        // Only when there is something to say. On the overwhelming majority of devices the pepper
        // is hardware-backed and this row would be noise; where it is not, the PIN's real cost to
        // guess is nothing like the cost this screen otherwise implies, and the user is entitled to
        // know that before choosing one. Shown only once a lock exists, since there is no pepper
        // and nothing to warn about before then.
        if (snapshot.lockEnabled && !snapshot.pinPepperLevel.isHardwareBacked()) {
            lockCard.addViewSpaced(
                TextView(this).apply {
                    text = getString(R.string.security_pin_pepper_software_warning)
                    textSize = 13f
                    setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10))
                    applyWarningCalloutTheme(this@SecuritySettingsActivity, this)
                },
                topDp = 10,
                bottomDp = 0,
            )
        }

        val locationCard = container.addSection(R.string.security_section_location)
        val hostileLocationSettings = SecurityRuntime.graph(this).hostileLocationSettings
        hostileLocationSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_hostile_location_title)
            isChecked = snapshot.hostileLocationEnabled
            isEnabled = snapshot.lockEnabled
        }
        locationCard.addViewSpaced(hostileLocationSwitch, bottomDp = 4)
        hostileLocationIntro = caption(
            if (snapshot.lockEnabled) {
                getString(R.string.security_hostile_location_intro)
            } else {
                getString(R.string.security_hostile_location_requires_lock)
            },
        )
        locationCard.addViewSpaced(hostileLocationIntro, bottomDp = 0)
        hostileLocationSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressHostileLocationListener) return@setOnCheckedChangeListener
            // Confirmed: the most destructive control on the screen, and it relaunches the app.
            AlertDialog.Builder(this)
                .setTitle(
                    if (checked) R.string.security_hostile_location_confirm_enable_title
                    else R.string.security_hostile_location_confirm_disable_title,
                )
                .setMessage(
                    if (checked) R.string.security_hostile_location_confirm_enable_body
                    else R.string.security_hostile_location_confirm_disable_body,
                )
                .setPositiveButton(R.string.security_hostile_location_confirm_positive) { _, _ ->
                    applyHostileLocationProtection(hostileLocationSettings, checked)
                }
                .setNegativeButton(R.string.cancel) { _, _ -> revertHostileLocationSwitch(!checked) }
                .setOnCancelListener { revertHostileLocationSwitch(!checked) }
                .create()
                .showSecurely()
        }

        val notificationsCard = container.addSection(R.string.security_section_notifications)
        credentialGateSwitch = SwitchCompat(this).apply {
            text = getString(R.string.security_credential_gate_title)
            isChecked = snapshot.credentialGateEnabled
            isEnabled = snapshot.lockEnabled
        }
        notificationsCard.addViewSpaced(credentialGateSwitch, bottomDp = 4)
        notificationsCard.addViewSpaced(
            caption(getString(R.string.security_credential_gate_intro)),
            bottomDp = 10,
        )
        // Always visible: the relay exposure exists whether or not this toggle is on.
        notificationsCard.addViewSpaced(
            TextView(this).apply {
                text = getString(R.string.security_credential_gate_leak_warning)
                textSize = 13f
                setPadding(dpToPx(12), dpToPx(10), dpToPx(12), dpToPx(10))
                applyWarningCalloutTheme(this@SecuritySettingsActivity, this)
            },
            bottomDp = 0,
        )
        credentialGateSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressCredentialGateListener) return@setOnCheckedChangeListener
            if (checked) confirmEnableCredentialGate() else confirmDisableCredentialGate()
        }

        lockSwitch.setOnCheckedChangeListener { _, checked ->
            if (suppressLockToggleListener) return@setOnCheckedChangeListener
            onLockToggle(checked)
        }
        // commit()-backed Keystore write; a click listener may not do that on the main thread.
        biometricSwitch.setOnCheckedChangeListener { _, checked ->
            lifecycleScope.launch {
                withContext(SecurityWork) {
                    appLockStore.setBiometricEnabled(checked)
                    // Switching it off destroys the sealed keys, not just the setting.
                    if (!checked) {
                        SecurityRuntime.graph(this@SecuritySettingsActivity).biometricUnlockVault.destroy()
                    }
                }
            }
        }

        // Built hidden and filled asynchronously: the row needs Keystore and network work.
        encryptionSectionLabel = TextView(this).apply {
            text = getString(R.string.security_encryption_section)
            applySectionEyebrowLabel(this@SecuritySettingsActivity, this)
            visibility = View.GONE
        }
        container.addViewSpaced(encryptionSectionLabel, bottomDp = 6)
        encryptionCard = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
            visibility = View.GONE
        }
        panelCards += encryptionCard
        container.addViewSpaced(encryptionCard, bottomDp = 10)
        encryptionRowText = caption("")
        encryptionCard.addViewSpaced(encryptionRowText, bottomDp = 10)
        encryptionActionButton = Button(this).apply { visibility = View.GONE }
        encryptionCard.addViewSpaced(encryptionActionButton, bottomDp = 0)

        scrollView.addView(container)
        setContentView(scrollView)
        applyThemeToActivity(this)

        // Runs AFTER applyThemeToActivity, which repaints every ViewGroup flat `panel`.
        val bg = Color.parseColor(getStoredThemePalette(this).bg)
        scrollView.setBackgroundColor(bg)
        container.setBackgroundColor(bg)
        panelCards.forEach { applyPanelBackground(this, it) }

        // Ghost, not the accent-filled primary: these two are secondary actions.
        applyGhostButtonTheme(this, changePinButton)
        applyGhostButtonTheme(this, lockGraceButton)
        applyGhostButtonTheme(this, wipeThresholdButton)
        refreshEncryptionRow()
    }

    /** An eyebrow label outside a panel card; radius fixed at 14dp by STYLE_GUIDE.md §3. */
    private fun LinearLayout.addSection(titleRes: Int, bottomDp: Int = 10): LinearLayout {
        addViewSpaced(
            TextView(this@SecuritySettingsActivity).apply {
                setText(titleRes)
                applySectionEyebrowLabel(this@SecuritySettingsActivity, this)
            },
            bottomDp = 6,
        )
        val card = LinearLayout(this@SecuritySettingsActivity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dpToPx(14), dpToPx(12), dpToPx(14), dpToPx(12))
        }
        // Painted later, not here: applyThemeToViewTree repaints every ViewGroup flat `panel` and
        // would flatten the rounding. See the paint pass after applyThemeToActivity.
        panelCards += card
        addViewSpaced(card, bottomDp = bottomDp)
        return card
    }

    private fun caption(text: CharSequence): TextView = TextView(this).apply {
        this.text = text
        textSize = 13f
    }

    /** Skips the identity request when a local fact decides the row; the network may be hostile. */
    private fun refreshEncryptionRow() {
        lifecycleScope.launch {
            val activity = this@SecuritySettingsActivity
            val local = withContext(SecurityWork) {
                val pairing = PushRuntime.graph(activity).repository.pairingForAuthenticatedCall()
                Triple(
                    pairing != null && !pairing.deviceId.isNullOrBlank(),
                    SecurityRuntime.graph(activity).hostileLocationSettings.isEnabled(),
                    hasSecureLockScreen(activity),
                )
            }
            val (paired, hostileLocation, lockScreen) = local
            val status = withContext(SecurityWork) {
                probeEnrollment(EnrollmentVault(activity))
            }
            // SecurityWork, like the reads above: this pairing read is several decrypts plus AES.
            val statusDecides = status == EnrollmentStatus.KEY_INVALIDATED ||
                status.isEnrolled()
            val identity = if (paired && !hostileLocation && lockScreen && !statusDecides) {
                withContext(SecurityWork) { AndroidIdentitySource(activity).check() }
            } else {
                IdentityCheck.CouldNotCheck
            }
            if (isFinishing || isDestroyed) return@launch
            renderEncryptionRow(
                enrollmentRowFor(
                    paired = paired,
                    hostileLocation = hostileLocation,
                    hasSecureLockScreen = lockScreen,
                    status = status,
                    identity = identity,
                ),
            )
        }
    }

    private fun renderEncryptionRow(row: EnrollmentRow) {
        if (row is EnrollmentRow.Hidden) {
            encryptionSectionLabel.visibility = View.GONE
            // The card too, not just its contents: an empty bordered panel is a section that looks
            // broken rather than absent.
            encryptionCard.visibility = View.GONE
            encryptionRowText.visibility = View.GONE
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionSectionLabel.visibility = View.VISIBLE
        encryptionCard.visibility = View.VISIBLE
        applySectionEyebrowLabel(this, encryptionSectionLabel)
        encryptionRowText.visibility = View.VISIBLE
        encryptionRowText.setText(encryptionRowCopy(row))

        val action: Pair<Int, () -> Unit>? = when (row) {
            EnrollmentRow.ServerHeldKey,
            EnrollmentRow.NoIdentity,
            -> R.string.security_encryption_open_webmail to { openAccountWebmail() }

            EnrollmentRow.NotEnrolled ->
                R.string.security_encryption_set_up to { launchEnrollmentCeremony() }

            EnrollmentRow.KeyInvalidated ->
                R.string.security_encryption_set_up_again to { launchEnrollmentCeremony() }

            EnrollmentRow.Enrolled ->
                R.string.security_encryption_remove to { confirmRemoveEnrollment() }

            // Nothing the user can do from here fixes any of these.
            EnrollmentRow.HostileLocation,
            EnrollmentRow.NoSecureLockScreen,
            EnrollmentRow.CouldNotCheck,
            EnrollmentRow.Hidden,
            -> null
        }

        if (action == null) {
            encryptionActionButton.visibility = View.GONE
            return
        }
        encryptionActionButton.visibility = View.VISIBLE
        encryptionActionButton.setText(action.first)
        encryptionActionButton.setOnClickListener { action.second() }
        if (row is EnrollmentRow.Enrolled) {
            applyDangerButtonTheme(this, encryptionActionButton)
        } else {
            applyPrimaryButtonTheme(this, encryptionActionButton)
        }
    }

    private fun encryptionRowCopy(row: EnrollmentRow): Int = when (row) {
        EnrollmentRow.Hidden -> R.string.empty_string
        EnrollmentRow.HostileLocation -> R.string.security_encryption_hostile_location
        EnrollmentRow.NoSecureLockScreen -> R.string.security_encryption_no_lock_screen
        EnrollmentRow.KeyInvalidated -> R.string.security_encryption_invalidated
        EnrollmentRow.Enrolled -> R.string.security_encryption_enrolled
        EnrollmentRow.ServerHeldKey -> R.string.security_encryption_server_held
        EnrollmentRow.NoIdentity -> R.string.security_encryption_no_identity
        EnrollmentRow.CouldNotCheck -> R.string.security_encryption_could_not_check
        EnrollmentRow.NotEnrolled -> R.string.security_encryption_not_enrolled
    }

    private fun launchEnrollmentCeremony() {
        startActivity(Intent(this, DeviceEnrollmentActivity::class.java))
    }

    /** Built from the pairing's own `serverUrl`, never from anything a response supplied —
     *  `openWebmail` refuses a non-first-party URL rather than degrading to a browser launch. */
    private fun openAccountWebmail() {
        lifecycleScope.launch {
            val serverUrl = withContext(SecurityWork) {
                PushRuntime.graph(this@SecuritySettingsActivity)
                    .repository.pairingForAuthenticatedCall()?.serverUrl
            }
            val url = serverUrl?.let { webmailHomeUrl(it) }
            val opened = url != null &&
                openWebmail(this@SecuritySettingsActivity, serverUrl, url)
            if (!opened) {
                Toast.makeText(
                    this@SecuritySettingsActivity,
                    R.string.security_encryption_webmail_failed,
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    /** Confirmed: destructive, and only reversible by another two-device ceremony. */
    private fun confirmRemoveEnrollment() {
        AlertDialog.Builder(this)
            .setTitle(R.string.security_encryption_remove_title)
            .setMessage(R.string.security_encryption_remove_body)
            .setPositiveButton(R.string.security_encryption_remove_confirm) { _, _ ->
                lifecycleScope.launch {
                    // clear() must be inside the block; code after withContext resumes cancellably.
                    val leftBehind = withContext(SecurityWork) {
                        try {
                            EnrollmentTeardown.destroyAndReport(
                                this@SecuritySettingsActivity,
                            )
                        } finally {
                            // Not ProcessState.resetAll(): unenroll is not a session boundary.
                            EnrollmentSession.clear()
                        }
                    }
                    if (leftBehind.isNotEmpty()) {
                        android.util.Log.e(
                            "SecuritySettings",
                            "Enrollment removal left $leftBehind behind",
                        )
                    }
                    if (isFinishing || isDestroyed) return@launch
                    // The enqueued report probes live state, so a half-failed teardown is reported
                    // honestly rather than as a removal that did not happen.
                    Toast.makeText(
                        this@SecuritySettingsActivity,
                        R.string.security_encryption_removed,
                        Toast.LENGTH_SHORT,
                    ).show()
                    refreshEncryptionRow()
                }
            }
            .setNegativeButton(android.R.string.cancel, null)
            .show()
    }

    /** Same re-entrancy hazard as [revertLockSwitch], guarded the same way. */
    private fun revertHostileLocationSwitch(checked: Boolean) {
        suppressHostileLocationListener = true
        hostileLocationSwitch.isChecked = checked
        suppressHostileLocationListener = false
    }

    private fun applyHostileLocationProtection(settings: HostileLocationSettings, enable: Boolean) {
        lifecycleScope.launch {
            // The relaunch is inside the non-cancellable unit; outside it, cancellation skips it.
            runSecurityChangeThenReset(
                workContext = SecurityWork,
                reset = {
                    AppRestart.relaunch(this@SecuritySettingsActivity)
                },
                change = {
                if (enable) disableAndPurgeDeviceContactSync()
                // Both directions need a fresh on-disk kypost_mail.db afterward.
                SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity)
                if (enable) {
                    // Also the metadata stores: push_state held 30 senders and subjects.
                    SecurityWipe.deletePlaintextMetadataStores(this@SecuritySettingsActivity)
                    // ...and attachments in shared Downloads, which sit OUTSIDE the sandbox.
                    // Reported, never fatal: the rows belong to a provider this app does not own,
                    // and refusing to enable protection over one is the wrong way to fail.
                    val stranded = runCatching {
                        DownloadedAttachmentLedger.deleteAll(this@SecuritySettingsActivity)
                    }.getOrElse {
                        android.util.Log.e(
                            "SecuritySettings",
                            "Could not erase downloaded attachments while enabling protection",
                            it,
                        )
                        listOf("<sweep failed>")
                    }
                    if (stranded.isNotEmpty()) {
                        android.util.Log.e(
                            "SecuritySettings",
                            "${stranded.size} saved attachment(s) remain in shared Downloads",
                        )
                        withContext(Dispatchers.Main) {
                            Toast.makeText(
                                this@SecuritySettingsActivity,
                                R.string.security_stranded_downloads_toast,
                                Toast.LENGTH_LONG,
                            ).show()
                        }
                    }
                    // Before the flag flips: an interruption must not leave a readable envelope.
                    tearDownEnrollmentForHostileLocation(this@SecuritySettingsActivity)
                }
                settings.setEnabled(enable)
                },
            )
        }
    }

    private fun lockGraceButtonLabel(millis: Long): String =
        getString(R.string.security_lock_grace_button, lockGraceLabel(millis))

    private fun lockGraceLabel(millis: Long): String = when (millis) {
        0L -> getString(R.string.security_lock_grace_immediately)
        else -> resources.getQuantityString(
            R.plurals.security_lock_grace_seconds,
            (millis / 1_000L).toInt(),
            (millis / 1_000L).toInt(),
        )
    }

    private fun wipeThresholdButtonLabel(attempts: Int?): String = getString(
        R.string.security_wipe_threshold_button,
        if (attempts == null) {
            getString(R.string.security_wipe_threshold_never)
        } else {
            resources.getQuantityString(R.plurals.security_wipe_threshold_attempts, attempts, attempts)
        },
    )

    /** Offers [LockoutPolicy.WIPE_THRESHOLD_CHOICES] plus "never"; the dialog states the cost. */
    private fun promptWipeThreshold() {
        val choices: List<Int?> = LockoutPolicy.WIPE_THRESHOLD_CHOICES + listOf<Int?>(null)
        val labels = choices.map { attempts ->
            if (attempts == null) {
                getString(R.string.security_wipe_threshold_never)
            } else {
                resources.getQuantityString(R.plurals.security_wipe_threshold_attempts, attempts, attempts)
            }
        }.toTypedArray()
        val current = choices.indexOf(appLockStore.wipeAfterAttempts()).takeIf { it >= 0 } ?: 0
        AlertDialog.Builder(this)
            .setTitle(R.string.security_wipe_threshold_dialog_title)
            .setMessage(R.string.security_wipe_threshold_dialog_message)
            .setSingleChoiceItems(labels, current) { dialog, which ->
                val chosen = choices[which]
                lifecycleScope.launch {
                    withContext(SecurityWork) { appLockStore.setWipeAfterAttempts(chosen) }
                    wipeThresholdButton.text = wipeThresholdButtonLabel(chosen)
                }
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    private fun promptLockGrace(settings: AppLockSettings) {
        val options = AppLockSettings.OPTIONS_MILLIS
        val labels = options.map { lockGraceLabel(it) }.toTypedArray()
        val current = options.indexOfFirst { it == settings.graceMillis() }.takeIf { it >= 0 } ?: 0
        AlertDialog.Builder(this)
            .setTitle(R.string.security_lock_grace_dialog_title)
            .setSingleChoiceItems(labels, current) { dialog, which ->
                settings.setGraceMillis(options[which])
                lockGraceButton.text = lockGraceButtonLabel(options[which])
                dialog.dismiss()
            }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    /** The synced rows live in the OS provider, which the in-memory database does not cover. */
    private suspend fun disableAndPurgeDeviceContactSync() {
        val graph = DeviceContactsRuntime.graph(this)
        runCatching {
            graph.settings.setEnabled(false)
            DeviceContactSyncScheduler.cancelPeriodic(this)
            graph.repository.deleteAllSyncedDeviceContacts()
            graph.accountManager.removeAccount()
        }.onFailure { android.util.Log.e("SecuritySettings", "Failed to purge device contacts", it) }
    }

    private fun onLockToggle(checked: Boolean) {
        if (checked) {
            promptSetPin()
        } else {
            promptDisableLock()
        }
    }

    private fun revertLockSwitch(checked: Boolean) {
        suppressLockToggleListener = true
        lockSwitch.isChecked = checked
        suppressLockToggleListener = false
    }

    /** Same re-entrancy hazard as [revertLockSwitch], guarded the same way. */
    private fun revertCredentialGateSwitch(checked: Boolean) {
        suppressCredentialGateListener = true
        credentialGateSwitch.isChecked = checked
        suppressCredentialGateListener = false
    }

    /** [onConfirmed] takes ownership of the PIN array and must zero it — [usePin] does that. */
    private fun promptEnterAndConfirmPin(onConfirmed: (CharArray) -> Unit, onCancelled: () -> Unit) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        val confirmField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.security_confirm_pin_hint)
        }
        val fieldsContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            addView(pinField)
            addView(confirmField)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.security_set_pin_title)
            .setView(fieldsContainer)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ ->
                // consumePin, not text.toString(): the PIN never becomes an unzeroable String.
                val pin = pinField.consumePin()
                val confirm = confirmField.consumePin()
                val policyError = pinPolicyMessage(PinPolicy.validate(pin))
                val matches = pin.contentEquals(confirm)
                java.util.Arrays.fill(confirm, ' ')
                when {
                    policyError != null -> {
                        java.util.Arrays.fill(pin, ' ')
                        Toast.makeText(this, policyError, Toast.LENGTH_LONG).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    !matches -> {
                        java.util.Arrays.fill(pin, ' ')
                        Toast.makeText(this, R.string.security_pin_mismatch, Toast.LENGTH_SHORT).show()
                        promptEnterAndConfirmPin(onConfirmed, onCancelled)
                    }
                    // onConfirmed owns the array from here and zeroes it when it is done.
                    else -> onConfirmed(pin)
                }
            }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setCancelable(false)
            // FLAG_SECURE is per-window and a Dialog has its own. See [showSecurely].
            .create()
            .showSecurely()
    }

    private fun pinPolicyMessage(result: PinPolicy.Result): String? = when (result) {
        PinPolicy.Result.Valid -> null
        PinPolicy.Result.TooShort -> resources.getQuantityString(
            R.plurals.security_pin_too_short,
            PinPolicy.MIN_LENGTH,
            PinPolicy.MIN_LENGTH,
        )
        PinPolicy.Result.TooLong -> resources.getQuantityString(
            R.plurals.security_pin_too_long,
            PinPolicy.MAX_LENGTH,
            PinPolicy.MAX_LENGTH,
        )
        PinPolicy.Result.NotNumeric -> getString(R.string.security_pin_not_numeric)
        PinPolicy.Result.TooCommon -> getString(R.string.security_pin_too_common)
    }

    private fun promptSetPin() {
        promptEnterAndConfirmPin(
            onConfirmed = { pin ->
                lifecycleScope.launch {
                    pin.usePin { entered ->
                        // setPin runs PBKDF2 and two commit()-backed Keystore writes.
                        withContext(SecurityWork) {
                            appLockStore.setPin(entered)
                            appLockStore.enableLock()
                            // Seal now, so the biometric switch below has something to offer.
                            SecurityRuntime.graph(this@SecuritySettingsActivity)
                                .appLockManager.resealForBiometric(entered)
                        }
                    }
                    changePinButton.visibility = View.VISIBLE
                    lockGraceButton.isEnabled = true
                    wipeThresholdButton.isEnabled = true
                    biometricSwitch.isEnabled = true
                    hostileLocationSwitch.isEnabled = true
                    hostileLocationIntro.text = getString(R.string.security_hostile_location_intro)
                    credentialGateSwitch.isEnabled = true
                }
            },
            onCancelled = { revertLockSwitch(false) },
        )
    }

    /** Requires the CURRENT PIN first (same verification as [promptDisableLock]) before minting a
     *  new one via the same enter+confirm flow [promptSetPin] uses. */
    private fun promptChangePin() {
        promptForPin(R.string.security_change_pin_title) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                // resolvePinAttempt, not `is Success`: this runs the same wipe threshold.
                val ok = resolvePinAttempt(appLockManager.verifyPinThrottled(entered))
                if (ok) {
                    promptEnterAndConfirmPin(
                        onConfirmed = { newPin ->
                            lifecycleScope.launch {
                                // changePin needs the OLD PIN, so `entered` is held across dialogs.
                                val changed = entered.usePin { old ->
                                    newPin.usePin { fresh -> changePin(oldPin = old, newPin = fresh) }
                                }
                                if (!changed) {
                                    Toast.makeText(
                                        this@SecuritySettingsActivity,
                                        R.string.security_change_pin_secret_unreadable,
                                        Toast.LENGTH_LONG,
                                    ).show()
                                }
                            }
                        },
                        onCancelled = { java.util.Arrays.fill(entered, ' ') },
                    )
                } else {
                    java.util.Arrays.fill(entered, ' ')
                    Toast.makeText(this@SecuritySettingsActivity, R.string.security_pin_incorrect, Toast.LENGTH_SHORT).show()
                }
            }
        }
    }

    private suspend fun changePin(oldPin: CharArray, newPin: CharArray): Boolean = withContext(SecurityWork) {
        val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
        val securePairingStore = PushRuntime.graph(this@SecuritySettingsActivity).securePairingStore
        val gateEnabled = appLockStore.isCredentialPinGateEnabled()
        val salt = appLockStore.credentialSalt()

        val pairing = if (gateEnabled && salt != null) {
            // deriveKeysOrNull, not deriveKeys: an unreadable Keystore pepper must abort the change,
            // not kill the coroutine mid-protocol. Nothing has been written yet, so the old PIN
            // stays authoritative and there is nothing to roll back.
            val oldKeys = CredentialCipher.deriveKeysOrNull(oldPin, salt) ?: return@withContext false
            securePairingStore.pairingSnapshot(oldKeys)
        } else {
            null
        }

        // ABORT BEFORE THE DESTRUCTIVE WRITE: a failed unwrap must not overwrite the PIN hash.
        val hasPairingToProtect = gateEnabled && salt != null && securePairingStore.needsCredentialRewrap().not() &&
            securePairingStore.pairingSnapshot(null) != null
        if (hasPairingToProtect && pairing?.deviceSecret.isNullOrBlank()) {
            android.util.Log.e(
                "SecuritySettings",
                "Refusing to change the PIN: the wrapped device secret could not be read with the old PIN",
            )
            return@withContext false
        }

        // PHASE 1 — stage the new wrapping while the OLD PIN is still authoritative. Nothing is
        // swapped yet, so a death here costs only an orphaned staged blob that the next successful
        // savePairing clears. Without this the window between setPin and the re-wrap below stranded
        // the device secret permanently, and the relay's eventual 409 read as "re-pair this device",
        // which deletes the mailbox. See [SecurePairingStore.stagePendingSecret].
        // Non-null together or not at all: both phases below act on the same wrapped secret.
        val secretToRewrap = pairing?.takeIf { !it.deviceSecret.isNullOrBlank() }
        if (gateEnabled && salt != null && secretToRewrap != null) {
            // Still ahead of the destructive write, so aborting here stages nothing and leaves the
            // old PIN the only one that opens anything.
            val newKeys = CredentialCipher.deriveKeysOrNull(newPin, salt) ?: return@withContext false
            securePairingStore.stagePendingSecret(secretToRewrap.deviceSecret!!, newKeys)
        }

        // PHASE 2 — swap the verifier. From here the new PIN is the only one that opens the app,
        // and the staged wrapping above is the copy it can read.
        appLockStore.setPin(newPin)
        // The sealed blob still holds the old PIN's keys until this runs.
        appLockManager.resealForBiometric(newPin)

        if (gateEnabled && salt != null) {
            // PHASE 3 — promote: re-derive under the new PIN and cache, so savePairing's gate-on
            // branch can wrap. The savePairing below is what clears the staged copy (see
            // SecurePairingStore's SecretWrite.Wrapped branch) — for a while this comment claimed
            // that and the code did not, leaving the staged blob on disk after every PIN change.
            // Failing here is survivable: the staged blob keeps the secret readable until a later
            // save promotes it.
            appLockManager.deriveAndCacheCredentialKeys(newPin)
            if (secretToRewrap != null) {
                PushRuntime.graph(this@SecuritySettingsActivity).repository.savePairing(secretToRewrap)
            }
        }
        true
    }

    /** `deriveAndCacheCredentialKeys`, not `verifyPinThrottled`: [disableLock] needs the key. */
    private fun promptDisableLock() {
        promptForPin(
            titleRes = R.string.security_confirm_disable_title,
            onCancelled = { revertLockSwitch(true) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                val ok = resolvePinAttempt(entered.usePin { appLockManager.deriveAndCacheCredentialKeys(it) })
                if (ok) disableLock() else revertLockSwitch(true)
            }
        }
    }

    /** Nothing here wipes anything: a failed unwrap refuses the toggle instead. */
    private suspend fun disableLock() {
        val settings = SecurityRuntime.graph(this).hostileLocationSettings
        data class PriorState(val hostileLocation: Boolean, val credentialGate: Boolean)

        // commit()-backed and Keystore-opening, so they belong on [SecurityWork].
        val prior = withContext(SecurityWork) {
            PriorState(
                hostileLocation = settings.isEnabled(),
                credentialGate = appLockStore.isCredentialPinGateEnabled(),
            ).also { settings.setEnabled(false) }
        }

        val appLockManager = SecurityRuntime.graph(this).appLockManager

        if (prior.credentialGate) {
            // Unwrap BEFORE the verifier is cleared, or an interruption strands the secret.
            val unwrapped = withContext(SecurityWork) { unwrapCurrentPairing() }
            if (!unwrapped) {
                // Refuse the toggle; a credential we cannot read is no reason to delete mail.
                withContext(SecurityWork) { settings.setEnabled(prior.hostileLocation) }
                revertLockSwitch(true)
                Toast.makeText(this, R.string.security_disable_lock_unwrap_failed, Toast.LENGTH_LONG).show()
                return
            }
            withContext(SecurityWork) { appLockStore.setCredentialPinGateEnabled(false) }
        }

        withContext(SecurityWork) {
            appLockStore.reset()
            // The sealed keys belong to the PIN that was just discarded. Leaving them would keep a
            // biometric-openable copy of a credential the user has asked the app to forget.
            SecurityRuntime.graph(this@SecuritySettingsActivity).biometricUnlockVault.destroy()
            // Nothing may still hold a PIN-derived key once the PIN is gone: a pairing saved later
            // in this session would otherwise be re-wrapped behind a gate that is now off.
            appLockManager.dropCredentialKeys()
        }

        if (prior.hostileLocation) {
            runSecurityChangeThenReset(
                workContext = SecurityWork,
                change = { SecurityWipe.closeAndDeleteDatabase(this@SecuritySettingsActivity) },
                reset = {
                    AppRestart.relaunch(this@SecuritySettingsActivity)
                },
            )
            return
        }

        changePinButton.visibility = View.GONE
        lockGraceButton.isEnabled = false
        wipeThresholdButton.isEnabled = false
        biometricSwitch.isChecked = false
        biometricSwitch.isEnabled = false
        hostileLocationSwitch.isEnabled = false
        hostileLocationIntro.text = getString(R.string.security_hostile_location_requires_lock)
        credentialGateSwitch.isEnabled = false
    }

    private fun confirmEnableCredentialGate() {
        AlertDialog.Builder(this)
            .setTitle(R.string.security_credential_gate_warning_title)
            .setMessage(R.string.security_credential_gate_warning_body)
            .setPositiveButton(R.string.security_credential_gate_warning_confirm) { _, _ -> promptCredentialGatePin(enabling = true) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> revertCredentialGateSwitch(false) }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    private fun confirmDisableCredentialGate() {
        promptCredentialGatePin(enabling = false)
    }

    /** The PIN is re-entered so a fresh key is available to re-wrap or unwrap in the same step. */
    private fun promptCredentialGatePin(enabling: Boolean) {
        promptForPin(
            titleRes = R.string.security_credential_gate_pin_title,
            onCancelled = { revertCredentialGateSwitch(!enabling) },
        ) { entered ->
            lifecycleScope.launch {
                val appLockManager = SecurityRuntime.graph(this@SecuritySettingsActivity).appLockManager
                if (!resolvePinAttempt(entered.usePin { appLockManager.deriveAndCacheCredentialKeys(it) })) {
                    revertCredentialGateSwitch(!enabling)
                    return@launch
                }
                withContext(SecurityWork) {
                    if (enabling) {
                        // Flag first: rewrapPairingIfNeeded checks it as a precondition. A failure
                        // after this point is retried on the next PIN unlock, which is idempotent.
                        appLockStore.setCredentialPinGateEnabled(true)
                        rewrapPairingIfNeeded(this@SecuritySettingsActivity, appLockManager)
                    } else {
                        // Unwrap first, flag second: reversed, an interruption between the two
                        // leaves a wrapped secret that nothing will ever unwrap again.
                        if (!unwrapCurrentPairing()) {
                            withContext(Dispatchers.Main) {
                                revertCredentialGateSwitch(true)
                                Toast.makeText(
                                    this@SecuritySettingsActivity,
                                    R.string.security_disable_lock_unwrap_failed,
                                    Toast.LENGTH_LONG,
                                ).show()
                            }
                            return@withContext
                        }
                        appLockStore.setCredentialPinGateEnabled(false)
                        // Drop the keys: a later save would re-wrap behind a gate that is now off.
                        appLockManager.dropCredentialKeys()
                    }
                }
            }
        }
    }

    /** The inverse of [rewrapPairingIfNeeded]; "no pairing at all" counts as success. */
    private suspend fun unwrapCurrentPairing(): Boolean {
        val store = PushRuntime.graph(this).securePairingStore
        if (!store.hasStoredPairing()) return true
        val credentialKeys = SecurityRuntime.graph(this).appLockManager.cachedCredentialKeys()
            ?: return false
        val currentPairing = store.pairingSnapshot(credentialKeys) ?: return false
        if (currentPairing.deviceSecret.isNullOrBlank()) return false
        // gateEnabled = false is the POINT of this function, not an omission: the caller is turning
        // the credential gate off, so the secret is deliberately written back in the clear. This is
        // the one call site in the app where a plaintext write is correct, which is precisely why
        // the posture is now stated rather than inferred from a missing key.
        store.savePairing(currentPairing, gateEnabled = false)
        return true
    }

    /** Single-field PIN prompt shared by the change-PIN, disable-lock and credential-gate flows. */
    private fun promptForPin(titleRes: Int, onCancelled: () -> Unit = {}, onEntered: (CharArray) -> Unit) {
        val pinField = android.widget.EditText(this).apply {
            inputType = android.text.InputType.TYPE_CLASS_NUMBER or android.text.InputType.TYPE_NUMBER_VARIATION_PASSWORD
            hint = getString(R.string.unlock_pin_hint)
        }
        AlertDialog.Builder(this)
            .setTitle(titleRes)
            .setView(pinField)
            .setPositiveButton(R.string.security_set_pin_confirm) { _, _ -> onEntered(pinField.consumePin()) }
            .setNegativeButton(android.R.string.cancel) { _, _ -> onCancelled() }
            .setCancelable(false)
            // See [promptEnterAndConfirmPin] and [showSecurely].
            .create()
            .showSecurely()
    }
}
