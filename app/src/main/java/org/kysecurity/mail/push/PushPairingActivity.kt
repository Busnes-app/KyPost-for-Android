package org.kysecurity.mail.push

import android.Manifest
import android.content.pm.PackageManager
import android.os.Bundle
import android.content.Intent
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.BaseAdapter
import android.widget.Button
import android.widget.ListView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.activity.viewModels
import androidx.core.content.ContextCompat
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import com.google.android.material.chip.Chip
import com.google.android.material.progressindicator.LinearProgressIndicator
import org.kysecurity.mail.applyCardOutline
import org.kysecurity.mail.BuildConfig
import org.kysecurity.mail.R
import org.kysecurity.mail.applyDangerButtonTheme
import org.kysecurity.mail.applyGhostButtonTheme
import org.kysecurity.mail.applyKyPostTopBar
import org.kysecurity.mail.applyPanelBackground
import org.kysecurity.mail.applyPillChipTheme
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applySectionEyebrowLabel
import org.kysecurity.mail.StatusTone
import org.kysecurity.mail.applyStatusText
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.getStoredThemePalette
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.util.Date
import org.kysecurity.mail.signon.AuthenticatorPin
import org.kysecurity.mail.signon.KyIdentitySignOnActivity
import org.kysecurity.mail.signon.PendingPairingLink
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

class PushPairingActivity : LockedActivity() {
    private val viewModel: PushHomeViewModel by viewModels()

    private lateinit var historyList: ListView
    private lateinit var historyAdapter: PushHistoryAdapter
    private lateinit var btnResyncToken: Button
    private lateinit var btnUnpairDevice: Button
    private lateinit var btnReconnectServer: Button
    private lateinit var btnScanQr: Button
    private lateinit var btnPasswordPairing: Button
    private lateinit var btnKyIdentitySignOn: Button
    private lateinit var chipUseUnifiedPush: Chip
    private lateinit var chipUseFirebase: Chip

    private lateinit var statusText: TextView
    private lateinit var serverUrlText: TextView
    private lateinit var subscriberText: TextView
    private lateinit var deviceIdText: TextView
    private lateinit var lastSyncText: TextView
    private lateinit var syncErrorText: TextView
    private lateinit var transportText: TextView
    private lateinit var latestSenderText: TextView
    private lateinit var latestSubjectText: TextView
    private lateinit var latestKeywordsText: TextView
    private lateinit var historyEmptyText: TextView
    private lateinit var approvalPanel: View
    private lateinit var approvalCodeText: TextView
    private lateinit var approvalServerText: TextView
    private lateinit var approvalProgress: LinearProgressIndicator
    private lateinit var btnCancelApproval: Button
    private lateinit var pairingPanels: List<View>

    private val reviewLoginTaps = ReviewLoginTaps()
    private var reviewLoginArmed = false
    private var renderedUnifiedPush = false

    private val dateFormat: DateFormat = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)

    // Registered here and not in onCreateUnlocked: see QrScannerFactory for why the order of
    // these registrations has to be identical on every creation.
    private val qrScanner: QrScanner = ChannelQrScanner.create(this)

    private val notificationPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (!granted) {
            Toast.makeText(this, R.string.push_pairing_notifications_denied, Toast.LENGTH_SHORT).show()
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_push_pairing)
        setTitle(R.string.push_pairing_title)

        PushNotificationDispatcher.ensureChannel(this)
        requestNotificationPermissionIfNeeded()
        consumeDeepLink(intent)
        // Consumed: a recreation must not replay it. Deep links land in onCreate, never onNewIntent.
        intent.data = null

        initViews()
        applyTopInsetWithHeader(this, findViewById(R.id.pushPairingRoot), withActionBar = false)
        historyAdapter = PushHistoryAdapter(this)
        historyList.emptyView = historyEmptyText
        historyList.adapter = historyAdapter

        btnResyncToken.setOnClickListener { viewModel.resyncToken() }
        btnUnpairDevice.setOnClickListener { confirmAndUnpairDevice() }
        btnReconnectServer.setOnClickListener { confirmAndReconnect() }
        btnScanQr.setOnClickListener { scanQr() }
        btnCancelApproval.setOnClickListener { viewModel.cancelApproval() }
        btnPasswordPairing.setOnClickListener { startActivity(Intent(this, PasswordPairingActivity::class.java)) }
        btnKyIdentitySignOn.setOnClickListener { startActivity(Intent(this, KyIdentitySignOnActivity::class.java)) }
        chipUseUnifiedPush.setOnClickListener { viewModel.switchToUnifiedPush(this) }
        chipUseFirebase.setOnClickListener {
            if (reviewLoginArmed) onReviewLoginTap() else viewModel.switchToFirebase()
        }

        applyThemeToActivity(this)

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                launch { viewModel.reportApprovalResults { !isFinishing && !redirectedToUnlock } }
                launch {
                    viewModel.paired.collect {
                        org.kysecurity.mail.security.AppLockOffer.showIfDue(this@PushPairingActivity)
                        org.kysecurity.mail.contacts.KeptContactsPrompt.showIfNeeded(this@PushPairingActivity)
                    }
                }
                viewModel.uiState.collect { state -> render(state) }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(R.string.menu_pairing))
        // One filled button per group: Scan QR pairs; the other ways in and the paired device's
        // maintenance actions are secondary, and Unpair is destructive.
        applyGhostButtonTheme(this, btnResyncToken)
        applyDangerButtonTheme(this, btnUnpairDevice)
        applyGhostButtonTheme(this, btnReconnectServer)
        applyPrimaryButtonTheme(this, btnScanQr)
        // The waiting card's only action; it backs out, so it is secondary.
        applyGhostButtonTheme(this, btnCancelApproval)
        applySectionEyebrowLabel(this, findViewById(R.id.pushPairingApprovalCodeLabel))
        getStoredThemePalette(this).let { palette ->
            approvalProgress.setIndicatorColor(android.graphics.Color.parseColor(palette.accent))
            approvalProgress.trackColor = android.graphics.Color.parseColor(palette.line)
            // The code is what the user compares; the tree's grey remap would give it `ink` in dark mode.
            val strong = android.graphics.Color.parseColor(palette.inkStrong)
            approvalCodeText.setTextColor(strong)
            findViewById<TextView>(R.id.pushPairingApprovalTitle).setTextColor(strong)
        }
        applyGhostButtonTheme(this, btnPasswordPairing)
        applyGhostButtonTheme(this, btnKyIdentitySignOn)
        btnKyIdentitySignOn.visibility = if (signOnAvailable()) View.VISIBLE else View.GONE
        // A sign-on finished while the app lock had destroyed its activity; the host dialog still applies.
        PendingPairingLink.take()?.let(::confirmAndApplyPairing)
        applyPillChipTheme(this, chipUseUnifiedPush)
        applyPillChipTheme(this, chipUseFirebase)
        applyPanelBackground(this, historyEmptyText)
        applySectionEyebrowLabel(this, findViewById(R.id.pushPairingLatestTitle))
        applySectionEyebrowLabel(this, findViewById(R.id.pushPairingHistoryTitle))
    }

    override fun onNewIntent(intent: android.content.Intent) {
        super.onNewIntent(intent)
        // getIntent() keeps returning the creating Intent unless replaced, so recreation would replay it.
        setIntent(intent)
        if (redirectedToUnlock) return
        consumeDeepLink(intent)
        // Consumed: a recreation must not replay it.
        intent.data = null
    }

    /** KyAuth pins only the play applicationId, so the other flavors would be refused anyway. */
    private fun signOnAvailable() =
        BuildConfig.APPLICATION_ID == "org.kysecurity.mail" && AuthenticatorPin.trustedAuthenticator(this)

    private fun initViews() {
        historyList = findViewById(R.id.pushPairingHistoryList)
        btnScanQr = findViewById(R.id.btnScanQr)
        btnPasswordPairing = findViewById(R.id.btnPasswordPairing)
        btnPasswordPairing.visibility = if (BuildConfig.ENABLE_REVIEW_PAIRING) View.VISIBLE else View.GONE
        btnKyIdentitySignOn = findViewById(R.id.btnKyIdentitySignOn)
        statusText = findViewById(R.id.pushPairingStatus)
        serverUrlText = findViewById(R.id.pushPairingServerUrl)
        subscriberText = findViewById(R.id.pushPairingSubscriber)
        deviceIdText = findViewById(R.id.pushPairingDeviceId)
        lastSyncText = findViewById(R.id.pushPairingLastSync)
        syncErrorText = findViewById(R.id.pushPairingSyncError)
        transportText = findViewById(R.id.pushPairingTransport)
        latestSenderText = findViewById(R.id.pushPairingLatestSender)
        latestSubjectText = findViewById(R.id.pushPairingLatestSubject)
        latestKeywordsText = findViewById(R.id.pushPairingLatestKeywords)
        historyEmptyText = findViewById(R.id.pushPairingHistoryEmpty)
        btnResyncToken = findViewById(R.id.btnResyncToken)
        btnUnpairDevice = findViewById(R.id.btnUnpairDevice)
        btnReconnectServer = findViewById(R.id.btnReconnectServer)
        chipUseUnifiedPush = findViewById(R.id.chipUseUnifiedPush)
        chipUseFirebase = findViewById(R.id.chipUseFirebase)
        approvalPanel = findViewById(R.id.pushPairingApprovalPanel)
        approvalCodeText = findViewById(R.id.pushPairingApprovalCode)
        approvalServerText = findViewById(R.id.pushPairingApprovalServer)
        approvalProgress = findViewById(R.id.pushPairingApprovalProgress)
        btnCancelApproval = findViewById(R.id.btnCancelApproval)
        pairingPanels = listOf(
            findViewById(R.id.pushPairingMainPanel),
            findViewById(R.id.pushPairingHistoryTitle),
            findViewById(R.id.pushPairingHistoryPanel),
        )
    }

    /** The waiting card replaces the whole screen while a registration awaits web approval. */
    private fun renderApproval(approval: PendingApprovalUi?) {
        approvalPanel.visibility = if (approval == null) View.GONE else View.VISIBLE
        pairingPanels.forEach { it.visibility = if (approval == null) View.VISIBLE else View.GONE }
        if (approval == null) return
        // Grouped like the web prompt ("048 213"); TalkBack reads it digit by digit.
        approvalCodeText.text = approval.approvalCode.chunked(3).joinToString(" ")
        approvalCodeText.contentDescription = approval.approvalCode.toList().joinToString(" ")
        approvalServerText.text = getString(R.string.push_pairing_approval_server, approval.serverHost)
    }

    private fun render(state: PushHomeUiState) {
        renderApproval(state.pendingApproval)
        val baseStatus = getString(
            if (state.pairing == null) R.string.push_pairing_status_not_paired else R.string.push_pairing_status_paired,
        )
        val none = getString(R.string.push_pairing_value_none)
        statusText.text = if (state.pairing == null) {
            baseStatus
        } else {
            val modeLabel = getString(
                if (state.deliveryMode == DeliveryMode.PULL) R.string.push_pairing_mode_pull
                else R.string.push_pairing_mode_push,
            )
            getString(R.string.push_pairing_status_with_mode, baseStatus, modeLabel)
        }
        applyStatusText(this, statusText, if (state.pairing == null) StatusTone.NEUTRAL else StatusTone.SUCCESS)
        serverUrlText.text = getString(R.string.push_pairing_server, state.pairing?.serverUrl ?: none)
        subscriberText.text =
            getString(R.string.push_pairing_subscriber, state.pairing?.subscriberId?.let { maskTail(it, 6) } ?: none)
        deviceIdText.text = getString(R.string.push_pairing_device_id, state.pairing?.deviceId ?: none)
        lastSyncText.text = getString(
            R.string.push_pairing_last_sync,
            state.lastTokenSyncAtEpochMs?.let { dateFormat.format(Date(it)) } ?: none,
        )

        if (state.syncError.isNullOrBlank()) {
            syncErrorText.visibility = View.GONE
        } else {
            syncErrorText.visibility = View.VISIBLE
            syncErrorText.text = getString(R.string.push_pairing_sync_error, state.syncError)
            applyStatusText(this, syncErrorText, StatusTone.DANGER)
        }

        transportText.text = getString(R.string.push_pairing_transport, transportLabel(state.transport))

        latestSenderText.text =
            getString(R.string.push_pairing_latest_sender, state.latestPayload?.let { PushPayloadParser.title(it) } ?: none)
        latestSubjectText.text =
            getString(R.string.push_pairing_latest_subject, state.latestPayload?.let { PushPayloadParser.body(it) } ?: none)
        latestKeywordsText.text =
            getString(R.string.push_pairing_latest_keywords, state.latestPayload?.keywords?.joinToString() ?: none)

        historyAdapter.submit(state.history)

        val paired = state.pairing != null
        val isUnifiedPush = state.transport == PushTransport.UNIFIED_PUSH
        btnResyncToken.isEnabled = !state.isWorking
        btnUnpairDevice.isEnabled = !state.isWorking
        // Only meaningful once something is stored to reset.
        btnReconnectServer.isEnabled = !state.isWorking && paired
        btnScanQr.isEnabled = !state.isWorking
        btnPasswordPairing.isEnabled = !state.isWorking
        btnKyIdentitySignOn.isEnabled = !state.isWorking
        chipUseUnifiedPush.isChecked = isUnifiedPush
        chipUseFirebase.isChecked = !isUnifiedPush
        // Not gated on pairing: the fdroid build cannot pair until a distributor has an endpoint.
        chipUseUnifiedPush.isEnabled = !state.isWorking && !isUnifiedPush
        // Before the first pairing there is nothing to switch, so on Play the chip counts taps
        // toward the review login instead; see ReviewLoginTaps.
        reviewLoginArmed = ReviewLoginTaps.armed(BuildConfig.FLAVOR, state.everPaired)
        renderedUnifiedPush = isUnifiedPush
        chipUseFirebase.isEnabled = !state.isWorking && ((paired && isUnifiedPush) || reviewLoginArmed)

        val message = state.localMessage
        if (!message.isNullOrBlank()) {
            Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            viewModel.consumeLocalMessage()
        }
    }

    private fun onReviewLoginTap() {
        // The chip group selected this chip on the way in, but nothing switched: put it back.
        chipUseUnifiedPush.isChecked = renderedUnifiedPush
        chipUseFirebase.isChecked = !renderedUnifiedPush
        if (reviewLoginTaps.tap()) startActivity(Intent(this, PasswordPairingActivity::class.java))
    }

    private fun requestNotificationPermissionIfNeeded() {
        if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.TIRAMISU) return

        val granted = ContextCompat.checkSelfPermission(
            this,
            Manifest.permission.POST_NOTIFICATIONS,
        ) == PackageManager.PERMISSION_GRANTED
        if (!granted) {
            notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
        }
    }

    private fun consumeDeepLink(intent: android.content.Intent?) {
        val data = intent?.dataString ?: return
        handleParsedPairing(NativePairingDeepLinkParser.parse(data))
    }

    private fun scanQr() {
        lifecycleScope.launch {
            runCatching {
                qrScanner.scan()
            }.onSuccess { raw ->
                if (raw.isNotBlank()) {
                    handleParsedPairing(NativePairingDeepLinkParser.parse(raw))
                }
            }.onFailure {
                Toast.makeText(this@PushPairingActivity, R.string.push_pairing_qr_scan_failed, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun handleParsedPairing(parsed: PairingParseResult) {
        when (parsed) {
            is PairingParseResult.Error -> Toast.makeText(this, parsed.reason, Toast.LENGTH_SHORT).show()
            is PairingParseResult.Success -> confirmAndApplyPairing(parsed.pairing)
        }
    }

    /** Every pairing source always confirms the destination server: a QR scan is not proof of trust. */
    private fun confirmAndApplyPairing(pairing: PairingData) {
        // From the store, not uiState: on the cold path uiState still serves its null initialValue.
        // A reconnect leaves the mailbox in place with no pairing, so "not paired" is not "nothing
        // to lose" — replacesAnotherAccount is the same signal attemptPairing purges on, and it is
        // the WHOLE condition. Or-ing in isPairedNow() made re-pairing the SAME account take the
        // replace branch, which tells the user another account's mail is about to be erased when
        // nothing is: attemptPairing purges on replacement alone, and the wording has to match.
        val repository = PushRuntime.graph(this).repository
        val replaces = repository.replacesAnotherAccount(pairing)
        val messageRes = when {
            replaces -> R.string.pairing_confirm_replace_message
            // Never a silent re-pin: say the certificate changed (owner decision, 2026-11-04).
            repository.repinsServer(pairing) -> R.string.pairing_confirm_repin_message
            else -> R.string.pairing_confirm_message
        }
        // The parsed host, never the raw `srv`: a raw URL in a trust prompt is a phishing surface.
        val shownHost = pairingUrlHost(pairing.serverUrl)
        if (shownHost == null) {
            Toast.makeText(this, R.string.pairing_confirm_bad_url, Toast.LENGTH_LONG).show()
            return
        }
        // The stored leaf pin refuses every other host, so a switch to another server could only
        // fail with a TLS error after the user agreed to it. Say how to switch instead.
        val pinnedHost = repository.currentTlsPin()?.host
        if (pinnedHost != null && !pinnedHost.equals(shownHost, ignoreCase = true)) {
            AlertDialog.Builder(this)
                .setTitle(R.string.pairing_confirm_title)
                .setMessage(getString(R.string.pairing_other_server_needs_unpair, pinnedHost, shownHost))
                .setPositiveButton(android.R.string.ok, null)
                .create()
                .showSecurely()
            return
        }
        // showSecurely: a BROWSABLE deep link raises this, so its accept button must not be coverable.
        AlertDialog.Builder(this)
            .setTitle(R.string.pairing_confirm_title)
            .setMessage(getString(messageRes, shownHost))
            .setPositiveButton(R.string.pairing_confirm_positive) { _, _ -> viewModel.applyPairing(pairing) }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    /** Unpairing now revokes server-side access (not just local state), so it gets the same
     *  confirm-before-destructive-action treatment as [confirmAndApplyPairing]. */
    private fun confirmAndUnpairDevice() {
        lifecycleScope.launch {
            // An unreadable database must not take the Unpair button with it: show the dialog
            // without the count, and let the purge's residue escalate to a wipe as before.
            val unsynced = runCatching {
                org.kysecurity.mail.contacts.ContactsRuntime.graph(this@PushPairingActivity).repository.unsyncedChangeCount()
            }.onFailure { android.util.Log.w("PushPairingActivity", "Could not count unsynced contact changes", it) }
                .getOrDefault(0)
            if (isFinishing || isDestroyed) return@launch
            // Owner decision Q2: contacts stay unless the user asks, warned about what has not synced.
            val removeContacts = android.widget.CheckBox(this@PushPairingActivity).apply {
                setText(R.string.push_pairing_unpair_remove_contacts)
            }
            val padding = (20 * resources.displayMetrics.density).toInt()
            val body = android.widget.LinearLayout(this@PushPairingActivity).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                setPadding(padding, padding / 2, padding, 0)
                addView(android.widget.TextView(this@PushPairingActivity).apply { setText(R.string.push_pairing_unpair_confirm_message) })
                if (unsynced > 0) {
                    addView(
                        android.widget.TextView(this@PushPairingActivity).apply {
                            text = resources.getQuantityString(R.plurals.push_pairing_unpair_unsynced, unsynced, unsynced)
                            setPadding(0, padding / 2, 0, 0)
                        },
                    )
                }
                addView(removeContacts)
            }
            AlertDialog.Builder(this@PushPairingActivity)
                .setTitle(R.string.push_pairing_unpair_confirm_title)
                .setView(android.widget.ScrollView(this@PushPairingActivity).apply { addView(body) })
                .setPositiveButton(R.string.push_pairing_unpair) { _, _ ->
                    viewModel.unpairDevice(keepContacts = !removeContacts.isChecked)
                }
                .setNegativeButton(R.string.cancel, null)
                .apply {
                    if (unsynced > 0) {
                        setNeutralButton(R.string.push_pairing_unpair_sync_now) { _, _ -> syncContactsThenConfirmUnpair() }
                    }
                }
                .create()
                .showSecurely()
        }
    }

    /** "Sync now" on the unpair dialog: reports the outcome, then asks again with the new count. */
    private fun syncContactsThenConfirmUnpair() {
        lifecycleScope.launch {
            val outcome = org.kysecurity.mail.contacts.ContactsRuntime.graph(this@PushPairingActivity).repository.sync()
            if (isFinishing || isDestroyed) return@launch
            val message = when (outcome) {
                org.kysecurity.mail.contacts.ContactSyncOutcome.Success -> getString(R.string.contacts_sync_success)
                is org.kysecurity.mail.contacts.ContactSyncOutcome.Retry -> outcome.message
                is org.kysecurity.mail.contacts.ContactSyncOutcome.ServiceUnavailable -> outcome.message
                org.kysecurity.mail.contacts.ContactSyncOutcome.AwaitingAccountChoice -> getString(R.string.contacts_sync_awaiting_choice)
                org.kysecurity.mail.contacts.ContactSyncOutcome.Unauthorized -> getString(R.string.contacts_sync_unauthorized)
                org.kysecurity.mail.contacts.ContactSyncOutcome.NotPaired -> getString(R.string.connection_mode_relay_not_paired)
            }
            Toast.makeText(this@PushPairingActivity, message, Toast.LENGTH_LONG).show()
            confirmAndUnpairDevice()
        }
    }

    /** Non-destructive, but it still ends the current pairing, so it confirms like the rest. */
    private fun confirmAndReconnect() {
        AlertDialog.Builder(this)
            .setTitle(R.string.push_pairing_reconnect_confirm_title)
            .setMessage(R.string.push_pairing_reconnect_confirm_message)
            .setPositiveButton(R.string.push_pairing_reconnect) { _, _ -> viewModel.reconnectToServer() }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    private inner class PushHistoryAdapter(context: android.content.Context) : BaseAdapter() {
        private val inflater = LayoutInflater.from(context)
        private var items: List<PushPayload> = emptyList()

        fun submit(payloads: List<PushPayload>) {
            items = payloads
            notifyDataSetChanged()
        }

        override fun getCount(): Int = items.size
        override fun getItem(position: Int): PushPayload = items[position]
        // Position, not messageId.hashCode(): a truncated hash is not a stable id.
        override fun getItemId(position: Int): Long = position.toLong()

        override fun getView(position: Int, convertView: View?, parent: ViewGroup): View {
            val view = convertView ?: inflater.inflate(R.layout.item_push_history, parent, false)
            val payload = items[position]
            val palette = getStoredThemePalette(view.context)

            val title = view.findViewById<TextView>(R.id.pushHistoryTitle)
            val subject = view.findViewById<TextView>(R.id.pushHistorySubject)
            val date = view.findViewById<TextView>(R.id.pushHistoryDate)

            title.text = PushPayloadParser.title(payload)
            subject.text = PushPayloadParser.body(payload)
            date.text = dateFormat.format(Date(payload.receivedAtEpochMs))

            val panelColor = android.graphics.Color.parseColor(palette.panel)
            val inkStrongColor = android.graphics.Color.parseColor(palette.inkStrong)
            val inkColor = android.graphics.Color.parseColor(palette.ink)
            (view as? androidx.cardview.widget.CardView)?.let {
                it.setCardBackgroundColor(panelColor)
                applyCardOutline(it.context, it)
            }
            title.setTextColor(inkStrongColor)
            subject.setTextColor(inkColor)
            date.setTextColor(inkColor)

            return view
        }
    }
}

private fun maskTail(value: String, keepLast: Int): String {
    if (value.length <= keepLast) return value
    val mask = "*".repeat(value.length - keepLast)
    return "$mask${value.takeLast(keepLast)}"
}

// Mirrors the badge labels on the web Notifications page; null means never synced yet.
private fun transportLabel(transport: PushTransport?): String = when (transport) {
    PushTransport.UNIFIED_PUSH -> "UnifiedPush"
    PushTransport.APNS -> "APNs"
    PushTransport.FCM -> "Firebase"
    null -> "Firebase (default)"
}
