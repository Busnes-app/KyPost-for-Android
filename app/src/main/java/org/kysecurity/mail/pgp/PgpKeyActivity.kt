package org.kysecurity.mail.pgp

import android.content.Intent
import android.graphics.Bitmap
import android.graphics.Color
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.ImageView
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.zxing.BarcodeFormat
import com.google.zxing.qrcode.QRCodeWriter
import org.kysecurity.mail.R
import org.kysecurity.mail.applyPrimaryButtonTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactsListActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

/** Saves via `queueUpdate` + `syncNowAsync()`; this app never calls per-contact REST endpoints. */
class PgpKeyActivity : LockedActivity() {

    private lateinit var qrImage: ImageView
    private lateinit var qrExpiresText: TextView
    private lateinit var qrMyFingerprintText: TextView
    private lateinit var qrStatusText: TextView
    private lateinit var scanStatusText: TextView
    private lateinit var scanNameText: TextView
    private lateinit var scanFingerprintText: TextView
    private lateinit var scanAddressesText: TextView
    private lateinit var confirmButton: Button
    private lateinit var scanButton: Button

    // lazy: pinnedPairingCallFactory needs a Context that does not exist at property-init time.
    private val client by lazy { PgpQrClient(callFactory = pinnedPairingCallFactory(this)) }
    private val bootstrapClient by lazy { PgpBootstrapClient(callFactory = pinnedPairingCallFactory(this)) }
    private val vaultOpener = AndroidVaultOpener(this)
    private var vaultOpenOffered = false
    private var ownQrJob: Job? = null
    private var pendingKey: PgpQrKeyDto? = null
    private var pendingVerified = false

    // Registered here and not in onCreateUnlocked: see QrScannerFactory for why the order of
    // these registrations has to be identical on every creation.
    private val qrScanner: org.kysecurity.mail.push.QrScanner =
        org.kysecurity.mail.push.ChannelQrScanner.create(this)

    private val pickContactLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        val uid = if (result.resultCode == RESULT_OK) {
            result.data?.getStringExtra(ContactsListActivity.EXTRA_RESULT_UID)
        } else {
            null
        }
        if (!uid.isNullOrBlank()) {
            saveKeyToContact(uid)
        }
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_pgp_key)
        setTitle(R.string.pgp_key_signing_title)
        applyThemeToActivity(this)
        applyTopInsetWithHeader(this, findViewById(R.id.pgpKeyRoot))

        qrImage = findViewById(R.id.pgpQrImage)
        qrExpiresText = findViewById(R.id.pgpQrExpiresText)
        qrMyFingerprintText = findViewById(R.id.pgpQrMyFingerprintText)
        qrStatusText = findViewById(R.id.pgpQrStatusText)
        scanStatusText = findViewById(R.id.pgpScanStatusText)
        scanNameText = findViewById(R.id.pgpScanNameText)
        scanFingerprintText = findViewById(R.id.pgpScanFingerprintText)
        scanAddressesText = findViewById(R.id.pgpScanAddressesText)
        confirmButton = findViewById(R.id.btnConfirmFingerprint)
        scanButton = findViewById(R.id.btnScanPgpQr)

        scanButton.setOnClickListener { scanQr() }
        confirmButton.setOnClickListener { onFingerprintConfirmed() }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyPrimaryButtonTheme(this, scanButton)
        applyPrimaryButtonTheme(this, confirmButton)
        mintAndRenderOwnQr()
    }

    private fun mintAndRenderOwnQr() {
        // The vault prompt pauses and resumes this screen; that resume must not mint a second code.
        if (ownQrJob?.isActive == true) return
        qrImage.visibility = View.GONE
        qrExpiresText.text = ""
        qrMyFingerprintText.visibility = View.GONE
        qrStatusText.text = getString(R.string.pgp_qr_my_code_loading)

        ownQrJob = lifecycleScope.launch {
            val pairing = PushRuntime.graph(this@PgpKeyActivity).repository.pairingForAuthenticatedCall()
            val deviceId = pairing?.deviceId
            val deviceSecret = pairing?.deviceSecret
            if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
                qrStatusText.text = getString(R.string.pgp_qr_my_code_not_paired)
                return@launch
            }
            openVaultOnce()

            when (val result = client.mintToken(pairing.serverUrl, deviceId, deviceSecret)) {
                is PgpQrTokenResult.Success -> renderQr(result.token, pairing.serverUrl, deviceId, deviceSecret)
                is PgpQrTokenResult.NoIdentity -> qrStatusText.text = getString(R.string.pgp_qr_my_code_no_identity)
                is PgpQrTokenResult.Unauthorized -> qrStatusText.text = getString(R.string.pgp_qr_my_code_unauthorized)
                is PgpQrTokenResult.ServiceUnavailable -> qrStatusText.text = getString(R.string.pgp_qr_my_code_unavailable)
                is PgpQrTokenResult.Retryable -> qrStatusText.text = result.message
            }
        }
    }

    /** Asked once per screen: declining leaves the server-reported fingerprint and a QR without one. */
    private suspend fun openVaultOnce() {
        if (vaultOpenOffered || EnrollmentSession.isHeld()) return
        vaultOpenOffered = true
        try {
            vaultOpener.open()
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
        }
    }

    private suspend fun renderQr(token: PgpQrTokenDto, serverUrl: String, deviceId: String, deviceSecret: String) {
        val own = ownFingerprint { bootstrapClient.fetch(serverUrl, deviceId, deviceSecret) }
        // Built from the paired origin: the server's `token.url` could point outside the TLS pin.
        val ownUrl = ownQrUrl(serverUrl, token.token, (own as? OwnFingerprint.Local)?.fingerprint)
        val bitmap = ownUrl?.let { runCatching { renderQrBitmap(it, QR_SIZE_PX) }.getOrNull() }
        if (bitmap == null) {
            qrStatusText.text = getString(R.string.pgp_qr_my_code_render_failed)
            return
        }
        qrImage.setImageBitmap(bitmap)
        qrImage.visibility = View.VISIBLE
        qrStatusText.text = ""
        qrExpiresText.text = getString(R.string.pgp_qr_my_code_expires, token.expiresAt)
        qrMyFingerprintText.text = when {
            own is OwnFingerprint.Local -> getString(R.string.pgp_qr_my_fingerprint_label, own.fingerprint)
            own is OwnFingerprint.ServerReported && own.fingerprint != null ->
                getString(R.string.pgp_qr_my_fingerprint_server_label, own.fingerprint)
            else -> getString(R.string.pgp_qr_my_fingerprint_unavailable)
        }
        qrMyFingerprintText.visibility = View.VISIBLE
    }

    private fun renderQrBitmap(content: String, sizePx: Int): Bitmap {
        val bitMatrix = QRCodeWriter().encode(content, BarcodeFormat.QR_CODE, sizePx, sizePx)
        val bitmap = Bitmap.createBitmap(sizePx, sizePx, Bitmap.Config.RGB_565)
        for (x in 0 until sizePx) {
            for (y in 0 until sizePx) {
                bitmap.setPixel(x, y, if (bitMatrix.get(x, y)) Color.BLACK else Color.WHITE)
            }
        }
        return bitmap
    }

    private fun scanQr() {
        lifecycleScope.launch {
            runCatching {
                qrScanner.scan()
            }.onSuccess { raw ->
                if (raw.isNotBlank()) {
                    handleScanned(raw)
                }
            }.onFailure {
                Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_canceled, Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun handleScanned(raw: String) {
        resetConfirmationState()
        val parsed = parsePgpQrKeyUrl(raw)
        if (parsed == null) {
            scanStatusText.text = getString(R.string.pgp_qr_scan_invalid)
            scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
            return
        }

        scanStatusText.text = getString(R.string.pgp_qr_my_code_loading)
        lifecycleScope.launch {
            when (val result = client.fetchKey(parsed.serverUrl, parsed.token)) {
                is PgpQrKeyResult.Success -> showFetchedKey(result.key, parsed.fingerprint)
                is PgpQrKeyResult.Forbidden -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_forbidden)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.NotFound -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_not_found)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.ServiceUnavailable -> {
                    scanStatusText.text = getString(R.string.pgp_qr_scan_unavailable)
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
                is PgpQrKeyResult.Retryable -> {
                    scanStatusText.text = result.message
                    scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
                }
            }
        }
    }

    private fun showFetchedKey(key: PgpQrKeyDto, expectedFingerprint: String?) {
        // Never the server's `fingerprint` field: it has no cryptographic tie to `publicKey`.
        val localFingerprint = PgpFingerprint.compute(key.publicKey)
        if (localFingerprint == null) {
            resetConfirmationState()
            scanStatusText.text = getString(R.string.pgp_qr_scan_unparseable_key)
            scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
            return
        }
        val check = checkScannedKey(expectedFingerprint, localFingerprint)
        if (check == ScannedKeyCheck.MISMATCH) {
            resetConfirmationState()
            scanStatusText.text = getString(R.string.pgp_qr_scan_mismatch)
            scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
            return
        }
        pendingKey = key
        pendingVerified = check == ScannedKeyCheck.CONFIRMED
        if (pendingVerified) {
            scanStatusText.text = getString(R.string.pgp_qr_scan_confirm_prompt)
            confirmButton.setText(R.string.pgp_qr_scan_confirm_button)
        } else {
            scanStatusText.text = getString(R.string.pgp_qr_scan_unverified_prompt)
            confirmButton.setText(R.string.pgp_qr_scan_save_unverified_button)
        }
        scanNameText.text = getString(R.string.pgp_qr_scan_name_label, key.name)
        scanNameText.visibility = View.VISIBLE
        scanFingerprintText.text = getString(R.string.pgp_qr_scan_fingerprint_label, localFingerprint)
        scanFingerprintText.visibility = View.VISIBLE
        // The fingerprint proves the KEY only; these addresses are the QR server's claim.
        val addresses = scannedAddresses(key)
        scanAddressesText.text = if (addresses.isEmpty()) {
            getString(R.string.pgp_qr_scan_addresses_none)
        } else {
            getString(R.string.pgp_qr_scan_addresses_label, addresses.joinToString("\n"))
        }
        scanAddressesText.visibility = View.VISIBLE
        confirmButton.visibility = View.VISIBLE
        scanButton.setText(R.string.pgp_qr_scan_scan_again_button)
    }

    private fun scannedAddresses(key: PgpQrKeyDto): List<String> =
        key.contactCard?.emails.orEmpty().map { it.value }.filter { it.isNotBlank() }

    private fun resetConfirmationState() {
        pendingKey = null
        pendingVerified = false
        scanNameText.visibility = View.GONE
        scanFingerprintText.visibility = View.GONE
        scanAddressesText.visibility = View.GONE
        confirmButton.visibility = View.GONE
    }

    private fun onFingerprintConfirmed() {
        val key = pendingKey ?: return
        if (key.contactCard != null) {
            showSaveChoiceDialog(key)
        } else {
            launchContactPicker()
        }
    }

    private fun showSaveChoiceDialog(key: PgpQrKeyDto) {
        val addresses = scannedAddresses(key)
        val verified = pendingVerified
        AlertDialog.Builder(this)
            .setTitle(R.string.pgp_qr_scan_save_choice_title)
            // Restate the binding at the point of commitment: "Create New Contact" writes every
            // address in the card, not just the name shown above it.
            .setMessage(
                if (addresses.isEmpty()) {
                    getString(R.string.pgp_qr_scan_addresses_none)
                } else {
                    getString(R.string.pgp_qr_scan_save_choice_body, addresses.joinToString("\n"))
                },
            )
            .setPositiveButton(R.string.pgp_qr_scan_save_new_button) { _, _ -> createNewContactFromCard(key, verified) }
            .setNegativeButton(R.string.pgp_qr_scan_save_existing_button) { _, _ -> launchContactPicker() }
            .create()
            .showSecurely()
    }

    /** Last gate: bound addresses come from the Room row, editable by any WRITE_CONTACTS app. */
    private suspend fun confirmBinding(name: String, addresses: List<String>): Boolean =
        kotlinx.coroutines.suspendCancellableCoroutine { continuation ->
            val body = if (addresses.isEmpty()) {
                getString(R.string.pgp_qr_bind_confirm_body_no_addresses, name)
            } else {
                getString(R.string.pgp_qr_bind_confirm_body, name, addresses.joinToString("\n"))
            }
            AlertDialog.Builder(this)
                .setTitle(R.string.pgp_qr_bind_confirm_title)
                .setMessage(body)
                .setPositiveButton(R.string.pgp_qr_bind_confirm_button) { _, _ ->
                    if (continuation.isActive) continuation.resumeWith(Result.success(true))
                }
                .setNegativeButton(android.R.string.cancel) { _, _ ->
                    if (continuation.isActive) continuation.resumeWith(Result.success(false))
                }
                .setOnCancelListener {
                    if (continuation.isActive) continuation.resumeWith(Result.success(false))
                }
                .create()
                .showSecurely()
        }

    private fun launchContactPicker() {
        pickContactLauncher.launch(
            Intent(this, ContactsListActivity::class.java).putExtra(ContactsListActivity.EXTRA_PICK_MODE, true),
        )
    }

    private fun createNewContactFromCard(key: PgpQrKeyDto, verified: Boolean) {
        val card = key.contactCard ?: return
        val dto = contactDtoFromCard(card, fallbackName = key.name, pgpKey = key.publicKey)
        lifecycleScope.launch {
            val graph = ContactsRuntime.graph(this@PgpKeyActivity)
            // A pin only when the key matched the scanned code; the addresses were shown before this point.
            graph.repository.queueCreate(dto, verifiedInPerson = verified)
            graph.coordinator.syncNowAsync()

            Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_saved_new, Toast.LENGTH_SHORT).show()
            resetConfirmationState()
            scanStatusText.text = ""
            scanButton.setText(R.string.pgp_qr_scan_scan_button)
        }
    }

    private fun saveKeyToContact(uid: String) {
        val key = pendingKey ?: return
        val verified = pendingVerified
        lifecycleScope.launch {
            val entity = DataRuntime.graph(this@PgpKeyActivity).database.contactDao().getByUid(uid)
            if (entity == null) {
                Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_invalid, Toast.LENGTH_SHORT).show()
                return@launch
            }
            // Restated at commitment: these are THIS contact's addresses, not the scanned card's.
            val boundAddresses = entity.toDto().emails.map { it.value }.filter { it.isNotBlank() }
            if (!confirmBinding(entity.fn, boundAddresses)) return@launch
            val dto = entity.toDto().copy(pgpKey = key.publicKey)

            val graph = ContactsRuntime.graph(this@PgpKeyActivity)
            // Verified rotation only when the key matched the scanned code.
            graph.repository.queueUpdate(dto, identityChanged = false, verifiedInPerson = verified)
            graph.coordinator.syncNowAsync()

            Toast.makeText(this@PgpKeyActivity, R.string.pgp_qr_scan_saved, Toast.LENGTH_SHORT).show()
            resetConfirmationState()
            scanStatusText.text = ""
            scanButton.setText(R.string.pgp_qr_scan_scan_button)
        }
    }

    companion object {
        private const val QR_SIZE_PX = 720
        private val QR_FINGERPRINT = Regex("[0-9A-F]{40}")

        /** Never the server's `url` field — see [renderQr]. Null if no valid URL can be built.
         *  [fingerprint] goes in the fragment, which is never sent to the server; only a v4 one fits. */
        internal fun ownQrUrl(serverUrl: String, token: String, fingerprint: String? = null): String? {
            if (token.isBlank()) return null
            val base = serverUrl.trimEnd('/').toHttpUrlOrNull() ?: return null
            val fp = fingerprint?.replace(" ", "")?.takeIf { QR_FINGERPRINT.matches(it) }
            return base.newBuilder()
                .addPathSegments("api/pgp/qr/key")
                .addQueryParameter("t", token)
                .fragment(fp?.let { "fp=$it" })
                .build()
                .toString()
        }

        /** [expected] is the code's `fp`; null means the code carried none. */
        internal fun checkScannedKey(expected: String?, computed: String): ScannedKeyCheck = when {
            expected == null -> ScannedKeyCheck.UNVERIFIED
            QR_FINGERPRINT.matches(expected) && expected == computed.replace(" ", "") -> ScannedKeyCheck.CONFIRMED
            else -> ScannedKeyCheck.MISMATCH
        }

        /** Parses a decoded QR payload into the `(serverUrl, token)` pair [PgpQrClient.fetchKey]
         *  expects. Returns null unless the payload is an `.../api/pgp/qr/key?t=...` URL. */
        internal fun parsePgpQrKeyUrl(raw: String): ParsedPgpQrKeyUrl? {
            val url = raw.trim().toHttpUrlOrNull() ?: return null
            if (url.encodedPath != "/api/pgp/qr/key") return null
            val token = url.queryParameter("t")?.takeIf { it.isNotBlank() } ?: return null
            val serverUrl = HttpUrl.Builder()
                .scheme(url.scheme)
                .host(url.host)
                .port(url.port)
                .build()
                .toString()
                .trimEnd('/')
            // Any fragment but `fp=` becomes "" so it fails the match rather than reading as absent.
            val fingerprint = url.fragment?.let { if (it.startsWith("fp=")) it.removePrefix("fp=") else "" }
            return ParsedPgpQrKeyUrl(serverUrl = serverUrl, token = token, fingerprint = fingerprint)
        }

        /** `ContactDto.fn` must be non-blank; a card's `fn` is `omitempty`, hence the fallback. */
        internal fun contactDtoFromCard(card: PgpQrContactCardDto, fallbackName: String, pgpKey: String): ContactDto =
            ContactDto(
                fn = card.fn?.takeIf { it.isNotBlank() } ?: fallbackName.ifBlank { "Unknown" },
                givenName = card.givenName,
                familyName = card.familyName,
                middleName = card.middleName,
                prefix = card.prefix,
                suffix = card.suffix,
                nickname = card.nickname,
                org = card.org,
                title = card.title,
                notes = card.notes,
                birthday = card.birthday,
                emails = card.emails,
                phones = card.phones,
                addresses = card.addresses,
                ims = card.ims,
                websites = card.websites,
                relations = card.relations,
                events = card.events,
                phoneticGivenName = card.phoneticGivenName,
                phoneticFamilyName = card.phoneticFamilyName,
                department = card.department,
                customFields = card.customFields,
                pronouns = card.pronouns,
                pgpKey = pgpKey,
            )
    }
}

internal data class ParsedPgpQrKeyUrl(val serverUrl: String, val token: String, val fingerprint: String? = null)

internal enum class ScannedKeyCheck { CONFIRMED, MISMATCH, UNVERIFIED }
