package org.kysecurity.mail

import android.content.Intent
import android.graphics.Color
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.text.TextUtils
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.lifecycle.lifecycleScope
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import com.google.android.material.navigation.NavigationBarView
import com.infomaniak.lib.richhtmleditor.RichHtmlEditorWebView
import org.kysecurity.mail.contacts.AddressBookSheet
import org.kysecurity.mail.contacts.RecipientCandidate
import org.kysecurity.mail.contacts.RecipientField
import org.kysecurity.mail.contacts.toRecipientCandidateOrNull
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.OutgoingAttachment
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.pgp.ClientEncryptedDraftSaver
import org.kysecurity.mail.pgp.DraftSaveOutcome
import org.kysecurity.mail.pgp.DraftHandoffMode
import org.kysecurity.mail.pgp.AndroidVaultOpener
import org.kysecurity.mail.pgp.ClientEncryptedSender
import org.kysecurity.mail.pgp.ClientSendOutcome
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientResolveClient
import org.kysecurity.mail.pgp.RoomLocalSignerKeys
import org.kysecurity.mail.pgp.openWebmail
import org.kysecurity.mail.pgp.webmailDraftsUrl
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.onEach
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.io.InputStream
import java.util.concurrent.Executors
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

class ComposeActivity : LockedActivity() {

    private lateinit var toInput: RecipientInputView
    private lateinit var ccInput: RecipientInputView
    private lateinit var bccInput: RecipientInputView
    private lateinit var subjectField: EditText
    private lateinit var bodyEditor: RichHtmlEditorWebView
    private lateinit var bodyPlaceholder: android.view.View
    private lateinit var attachButton: Chip
    private lateinit var attachmentChips: ChipGroup
    private lateinit var boldChip: Chip
    private lateinit var italicChip: Chip
    private lateinit var underlineChip: Chip
    private lateinit var linkChip: Chip
    private lateinit var detailsCard: android.view.View
    private lateinit var messageCard: android.view.View
    private lateinit var detailsDividers: List<android.view.View>
    private lateinit var messageDivider: android.view.View
    private lateinit var rootView: android.view.View
    private lateinit var bottomNav: NavigationBarView
    private lateinit var pgpChips: ChipGroup
    private lateinit var encryptChip: Chip
    private lateinit var signChip: Chip
    private lateinit var webmailChip: Chip
    private lateinit var keylessWarning: android.widget.TextView
    private val pgpController by lazy { ComposePgpController.from(this) }
    private var sendMenuItem: MenuItem? = null

    /** Key held only by the user and this device not enrolled: Send is withdrawn while it holds. */
    private var handoffOnlyAccount = false

    /** True when the encryption happens on this device and the send goes to `/api/mail/send-pgp`
     *  rather than `/api/mail/send`. From [PgpComposeState.clientSide]. */
    private var clientSideAccount = false

    /** The in-flight client-encrypted send; guards a double-tap from starting two sends. */
    private var sendJob: Job? = null
    private var handoffJob: Job? = null
    private val handoffOpener by lazy { AndroidVaultOpener(this) }
    private var handoffBusy = false
    private var handoffAttempt = 0L
    private val ioExecutor = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())

    /** The editor exports its HTML asynchronously, and a configuration change destroys this
     *  Activity before the callback can land — while the replacement reads [ComposeDraftCache] in
     *  `onCreate`, so a draft that arrives later is already too late. [onStop] therefore has to
     *  *already hold* the body, which is what this mirror is for. */
    private var mirroredBodyHtml: String = ""

    /** What [ComposeDraftCache] handed this instance on the way in, so a test can assert that a
     *  teardown did not throw the draft away. Holds no plaintext the cache did not already hold. */
    @androidx.annotation.VisibleForTesting
    internal var restoredDraftForTest: CachedDraft? = null
        private set

    @androidx.annotation.VisibleForTesting
    internal fun mirroredBodyHtmlForTest(): String = mirroredBodyHtml

    private val bodyMirror = object : Runnable {
        override fun run() {
            bodyEditor.exportHtml { mirroredBodyHtml = it }
            mainHandler.postDelayed(this, BODY_MIRROR_INTERVAL_MS)
        }
    }
    private val attachments = mutableListOf<OutgoingAttachment>()

    /** The in-flight preflight; cancelled so a late result cannot re-show a dismissed warning. */
    private var preflightJob: Job? = null

    /** The draft as sent, so the post-409 re-send reuses it byte-for-byte with one flag flipped. */
    private var sentDraft: MailDraft? = null

    /** Set once the relay confirms delivery, so [onStop] does not re-cache a message that has
     *  already been sent — which would otherwise reappear as a "restored draft" next time. */
    private var sendSucceeded = false

    /** The currently shown pickup-fallback/webmail-handoff dialog, if any — dismissed in
     *  [onDestroy] so it does not outlive the Activity's window. */
    private var activeDialog: AlertDialog? = null

    /** Encrypt/Sign as a restored draft left them, until [applyRestoredPgpToggles] can apply them. */
    private var restoredPgpToggles: Pair<Boolean, Boolean>? = null

    /** The draft restore and [applyPgpComposeState] land in either order; the second applies. */
    private var pgpChipListenersReady = false

    private fun applyRestoredPgpToggles() {
        if (!pgpChipListenersReady) return
        val (encrypt, sign) = restoredPgpToggles ?: return
        restoredPgpToggles = null
        // Encrypt first: signChip's listener turns Encrypt on by itself on a client-custody account.
        encryptChip.isChecked = encrypt
        signChip.isChecked = sign
    }

    private val pickAttachments = registerForActivityResult(
        ActivityResultContracts.OpenMultipleDocuments(),
    ) { uris -> if (!uris.isNullOrEmpty()) addAttachments(uris) }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        setContentView(R.layout.activity_compose)
        applyThemeToActivity(this)

        // Resolved by id, not by cast: layout-w600dp/activity_compose.xml uses a different root
        // element than the phone layout.
        rootView = findViewById(R.id.composeRoot)
        // Keeps the composition out of the saved-state Bundle, which system_server owns.
        rootView.isSaveFromParentEnabled = false
        applyTopInsetWithHeader(this, findViewById<View?>(R.id.composeContent) ?: rootView)

        bottomNav = findViewById(R.id.bottomNavigation)
        applyPrimaryNavigationInsets(this, bottomNav)
        setupPrimaryNavigation(this, bottomNav, R.id.nav_compose)
        applyPrimaryNavigationTheme(this, bottomNav)
        applyKyPostTopBar(this, getString(R.string.nav_compose))

        subjectField = findViewById(R.id.composeSubjectField)
        bodyEditor = findViewById(R.id.composeBodyEditor)
        // blockNetworkLoads: without it, pressing Reply fetched every remote image the sender embedded.
        bodyEditor.settings.apply {
            blockNetworkLoads = true
            allowContentAccess = false
            allowFileAccess = false
        }
        bodyPlaceholder = findViewById(R.id.composeBodyPlaceholder)
        attachButton = findViewById(R.id.composeAttachButton)
        attachmentChips = findViewById(R.id.composeAttachmentsCard)
        boldChip = findViewById(R.id.composeBold)
        italicChip = findViewById(R.id.composeItalic)
        underlineChip = findViewById(R.id.composeUnderline)
        linkChip = findViewById(R.id.composeLink)
        detailsCard = findViewById(R.id.composeDetailsCard)
        messageCard = findViewById(R.id.composeMessageCard)
        detailsDividers = listOf(
            findViewById(R.id.composeDetailsDivider1),
            findViewById(R.id.composeDetailsDivider2),
            findViewById(R.id.composeDetailsDivider3),
        )
        messageDivider = findViewById(R.id.composeMessageDivider)

        pgpChips = findViewById(R.id.composePgpChips)
        encryptChip = findViewById(R.id.composeEncryptChip)
        signChip = findViewById(R.id.composeSignChip)
        webmailChip = findViewById(R.id.composeWebmailChip)
        keylessWarning = findViewById(R.id.composeKeylessWarning)
        applyWarningCalloutTheme(this, keylessWarning)

        lifecycleScope.launch { applyPgpComposeState(pgpController.composeState()) }

        toInput = findViewById(R.id.composeToInput)
        ccInput = findViewById(R.id.composeCcInput)
        bccInput = findViewById(R.id.composeBccInput)
        toInput.setLabel(getString(R.string.email_to))
        ccInput.setLabel(getString(R.string.email_cc))
        bccInput.setLabel(getString(R.string.email_bcc))

        val contactDao = DataRuntime.graph(this).database.contactDao()
        val searchContacts: suspend (String) -> List<RecipientCandidate> = { query ->
            contactDao.search(query).mapNotNull { it.toRecipientCandidateOrNull() }
        }
        toInput.configure(searchContacts, onOpenAddressBook = ::openAddressBook)
        ccInput.configure(searchContacts)
        bccInput.configure(searchContacts)

        // Only while Encrypt is on: an empty recipient list short-circuits the initial check.
        val onRecipientsChanged = { if (encryptChip.isChecked) runPreflight() }
        toInput.onRecipientsChanged = onRecipientsChanged
        ccInput.onRecipientsChanged = onRecipientsChanged
        bccInput.onRecipientsChanged = onRecipientsChanged

        // A draft the app lock destroyed wins over an internal Reply/Forward prefill. A public
        // mailto/share request is a new composition, though: restoring an unrelated prior draft
        // silently replaces what the sending app asked the user to send.
        val restored = if (intent.isExternalComposeIntent()) {
            ComposeDraftCache.resetForNewSession()
            ComposeDraftCache.take() // Unseal so this new composition can survive lock teardown.
            null
        } else {
            ComposeDraftCache.take()
        }
        restoredDraftForTest = restored
        if (restored != null) {
            subjectField.setText(restored.subject)
            toInput.setInitialRecipients(restored.to)
            ccInput.setInitialRecipients(restored.cc)
            bccInput.setInitialRecipients(restored.bcc)
            attachments.addAll(restored.attachments)
            renderAttachmentChips()
            bodyEditor.setHtml(restored.bodyHtml)
            // Deferred rather than set directly: the chips' listeners are installed by
            // applyPgpComposeState, and re-checking Encrypt has to re-run the keyless preflight.
            restoredPgpToggles = restored.encrypt to restored.sign
            applyRestoredPgpToggles()
            // The restored draft already carries its own attachments; a handoff left over from an
            // abandoned forward must not be merged into it.
            ForwardAttachmentHandoff.clear()
            Toast.makeText(this, R.string.compose_draft_restored, Toast.LENGTH_SHORT).show()
        } else {
            val (to, subject, bodyHtml) = parseComposeIntent(intent, ::plainTextToHtml)
            subjectField.setText(subject)
            toInput.setInitialRecipients(to)
            bodyEditor.setHtml(bodyHtml)

            // A forward's attachments, handed over out-of-band because they are far too large for
            // an Intent extra — see [ForwardAttachmentHandoff].
            val forwarded = ForwardAttachmentHandoff.take()
            if (forwarded.isNotEmpty()) {
                // Re-checked HERE, not only in addAttachment: that guard covers files the user
                // picks, and a forward walked straight past it with attachment sizes the relay
                // chose. The producer bounds these too; this is the boundary that must hold.
                var held = 0L
                val accepted = forwarded.takeWhile { held += it.size; held <= MAX_ATTACHMENT_BYTES }
                if (accepted.size < forwarded.size) {
                    Toast.makeText(
                        this,
                        resources.getQuantityString(
                            R.plurals.forward_attachments_too_large,
                            forwarded.size - accepted.size,
                            forwarded.size - accepted.size,
                        ),
                        Toast.LENGTH_LONG,
                    ).show()
                }
                attachments.addAll(accepted)
                renderAttachmentChips()
            }

            // Handle attachments from sharing intents
            val streamUris = when (intent.action) {
                Intent.ACTION_SEND -> {
                    @Suppress("DEPRECATION")
                    intent.getParcelableExtra<Uri>(Intent.EXTRA_STREAM)?.let { listOf(it) }
                }
                Intent.ACTION_SEND_MULTIPLE -> {
                    @Suppress("DEPRECATION")
                    intent.getParcelableArrayListExtra<Uri>(Intent.EXTRA_STREAM)
                }
                else -> null
            }
            if (streamUris != null) {
                addAttachments(streamUris)
            }
        }

        boldChip.setOnClickListener { bodyEditor.toggleBold() }
        italicChip.setOnClickListener { bodyEditor.toggleItalic() }
        underlineChip.setOnClickListener { bodyEditor.toggleUnderline() }
        linkChip.setOnClickListener {
            if (linkChip.isChecked) {
                bodyEditor.unlink()
            } else {
                showCreateLinkDialog()
            }
        }

        lifecycleScope.launch {
            bodyEditor.editorStatusesFlow.collect { statuses ->
                boldChip.isChecked = statuses.isBold
                italicChip.isChecked = statuses.isItalic
                underlineChip.isChecked = statuses.isUnderlined
                linkChip.isChecked = statuses.isLinkSelected
            }
        }
        bodyEditor.isEmptyFlow
            .onEach { isEmpty -> bodyPlaceholder.visibility = if (isEmpty != false) android.view.View.VISIBLE else android.view.View.GONE }
            .launchIn(lifecycleScope)

        attachButton.setOnClickListener { pickAttachments.launch(arrayOf("*/*")) }
        applyToolbarChipsTheme()
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(R.string.nav_compose))
        applyPrimaryNavigationTheme(this, bottomNav)
        applyToolbarChipsTheme()
        applySendMenuItemTheme()
        applyEditorThemeCss()
        toInput.applyTheme()
        ccInput.applyTheme()
        bccInput.applyTheme()
        // post, not postDelayed: the first mirror has to exist before the first teardown can.
        mainHandler.removeCallbacks(bodyMirror)
        mainHandler.post(bodyMirror)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        if (redirectedToUnlock) return false
        val item = menu.add(0, MENU_SEND, 0, R.string.compose_send)
        item.setIcon(R.drawable.ic_send)
        item.setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS)
        sendMenuItem = item
        applySendMenuItemTheme()
        // The menu is created after the bootstrap may already have answered, so the availability
        // decision has to be re-applied here as well as when the state arrives.
        applySendAvailability()
        return super.onCreateOptionsMenu(menu)
    }

    /** Withdraws Send on an account this app cannot encrypt for. See [applyPgpComposeState]. */
    private fun applySendAvailability() {
        sendMenuItem?.isVisible = !handoffOnlyAccount
        sendMenuItem?.isEnabled = !handoffOnlyAccount && !handoffBusy
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_SEND -> {
                // Belt and braces against a stale menu: the item is hidden for a handoff-only
                // account, but a send that reached here would be a silent cleartext downgrade.
                if (handoffOnlyAccount) {
                    Toast.makeText(this, R.string.compose_send_needs_webmail, Toast.LENGTH_LONG).show()
                } else {
                    sendEmail()
                }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    private fun applySendMenuItemTheme() {
        val accent = Color.parseColor(getStoredThemePalette(this).accent)
        sendMenuItem?.icon?.mutate()?.setTint(readableOn(accent))
    }

    private fun openAddressBook() {
        AddressBookSheet { candidate, field ->
            val target = when (field) {
                RecipientField.TO -> toInput
                RecipientField.CC -> ccInput
                RecipientField.BCC -> bccInput
            }
            target.addRecipient(candidate.email, candidate.name)
        }.show(supportFragmentManager, AddressBookSheet.TAG)
    }

    private fun applyToolbarChipsTheme() {
        listOf(boldChip, italicChip, underlineChip, linkChip, attachButton, encryptChip, signChip, webmailChip).forEach {
            applyPillChipTheme(this, it)
        }
        // applyThemeToViewTree paints every ViewGroup flat `panel`; repaint root `bg` so cards pop.
        rootView.setBackgroundColor(Color.parseColor(getStoredThemePalette(this).bg))
        // Rounded panel cards behind each section — shared STYLE_GUIDE.md §3 Card/panel radius,
        // same applyPanelBackground precedent as Inbox's keyword-chip bar.
        applyPanelBackground(this, detailsCard)
        applyPanelBackground(this, messageCard)
        applyPanelBackground(this, attachmentChips)
        val line = Color.parseColor(getStoredThemePalette(this).line)
        detailsDividers.forEach { it.setBackgroundColor(line) }
        messageDivider.setBackgroundColor(line)
    }

    /** Views only — the rule itself is [org.kysecurity.mail.pgp.pgpComposeStateOf], unit-tested. */
    private fun applyPgpComposeState(state: PgpComposeState) {
        encryptChip.visibility = if (state.canEncrypt) View.VISIBLE else View.GONE
        signChip.visibility = if (state.canSign) View.VISIBLE else View.GONE
        webmailChip.visibility = if (state.handoffToWebmail) View.VISIBLE else View.GONE
        // Unenrolled client-custody: hidden chips send both flags false, a silent cleartext downgrade.
        handoffOnlyAccount = state.handoffToWebmail
        clientSideAccount = state.clientSide
        applySendAvailability()
        pgpChips.visibility =
            if (state.canEncrypt || state.canSign || state.handoffToWebmail) View.VISIBLE else View.GONE

        encryptChip.setOnCheckedChangeListener { _, checked ->
            if (checked) {
                runPreflight()
            } else {
                // Cancel rather than let a stale result land after the toggle has gone off — a
                // superseded preflight must never overwrite the newer (in this case: hidden) state.
                preflightJob?.cancel()
                hideKeylessWarning()
                // Sign-only is impossible: the relay accepts multipart/encrypted and rejects multipart/signed.
                // ponytail: lift this once the relay accepts a multipart/signed delivery — needs a
                // server change first.
                if (clientSideAccount) signChip.isChecked = false
            }
        }
        signChip.setOnCheckedChangeListener { _, checked ->
            if (checked && clientSideAccount && !encryptChip.isChecked) encryptChip.isChecked = true
        }
        webmailChip.setOnClickListener { handOffToWebmail() }

        // Last, so a restored draft's toggles go through the listeners above rather than around
        // them: checking Encrypt re-runs the preflight, and the two chips stay coupled.
        pgpChipListenersReady = true
        applyRestoredPgpToggles()
    }

    /** Cancels any running preflight first, so a slow earlier check cannot clobber a newer one. */
    private fun runPreflight() {
        val addresses = splitAddresses(
            toInput.commaJoinedRecipients(),
            ccInput.commaJoinedRecipients(),
            bccInput.commaJoinedRecipients(),
        )
        preflightJob?.cancel()
        preflightJob = lifecycleScope.launch {
            val keyless = pgpController.keylessRecipients(addresses)
            if (keyless.isEmpty()) {
                hideKeylessWarning()
            } else {
                keylessWarning.text =
                    getString(R.string.compose_pgp_no_key_on_file, keyless.joinToString(", "))
                keylessWarning.visibility = View.VISIBLE
            }
        }
    }

    private fun hideKeylessWarning() {
        keylessWarning.visibility = View.GONE
    }

    /** Also sets a min-height: the editor reports document height back as the WebView's height. */
    private fun applyEditorThemeCss() {
        val palette = getStoredThemePalette(this)
        val css = """
            html, body {
                min-height: 500px;
            }
            body {
                background-color: ${palette.bg};
                color: ${palette.inkStrong};
                font-family: sans-serif;
                font-size: 16px;
            }
            a { color: ${palette.accent}; }
        """.trimIndent()
        bodyEditor.addCss(css, id = "kypost-compose-theme")
    }

    private fun showCreateLinkDialog() {
        val padding = (16 * resources.displayMetrics.density).toInt()
        val urlField = EditText(this).apply { hint = getString(R.string.compose_link_dialog_url_hint) }
        val textField = EditText(this).apply { hint = getString(R.string.compose_link_dialog_text_hint) }
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(padding, padding, padding, 0)
            addView(urlField)
            addView(textField)
        }
        AlertDialog.Builder(this)
            .setTitle(R.string.compose_link_dialog_title)
            .setView(container)
            .setPositiveButton(R.string.compose_link_dialog_add) { _, _ ->
                val url = urlField.text.toString().trim()
                if (url.isNotBlank()) bodyEditor.createLink(textField.text.toString().trim(), url)
            }
            .setNegativeButton(R.string.cancel, null)
            .create()
            .showSecurely()
    }

    private fun plainTextToHtml(text: String): String {
        if (text.isEmpty()) return ""
        return TextUtils.htmlEncode(text).replace("\n", "<br>")
    }

    /** Sequential, not concurrent: each is checked against the remaining budget before adding. */
    private fun addAttachments(uris: List<Uri>) {
        lifecycleScope.launch {
            for (uri in uris) {
                if (isFinishing || isDestroyed) return@launch
                addAttachment(uri)
            }
        }
    }

    /** Reads on IO and enforces the 25 MB cap from the declared size, before the bytes are heap. */
    private suspend fun addAttachment(uri: Uri) {
        val resolver = contentResolver
        val budget = MAX_ATTACHMENT_BYTES - attachments.sumOf { it.size.toLong() }

        val picked = withContext(Dispatchers.IO) {
            var name = "attachment"
            var declaredSize = -1L
            runCatching {
                resolver.query(uri, null, null, null, null)?.use { cursor ->
                    if (cursor.moveToFirst()) {
                        val nameIdx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                        if (nameIdx >= 0 && !cursor.isNull(nameIdx)) name = cursor.getString(nameIdx)
                        val sizeIdx = cursor.getColumnIndex(OpenableColumns.SIZE)
                        if (sizeIdx >= 0 && !cursor.isNull(sizeIdx)) declaredSize = cursor.getLong(sizeIdx)
                    }
                }
            }
            // Refuse on the advertised size first, so an oversized file is never opened at all.
            if (declaredSize > budget) return@withContext PickedAttachment.TooLarge(name)

            val bytes = try {
                resolver.openInputStream(uri)?.use { readAtMost(it, budget, declaredSize) }
            } catch (e: AttachmentTooLargeException) {
                // The provider under-reported, or omitted, OpenableColumns.SIZE.
                android.util.Log.i(TAG, "Picked attachment exceeded the remaining budget", e)
                return@withContext PickedAttachment.TooLarge(name)
            } catch (e: kotlinx.coroutines.CancellationException) {
                // Inside withContext: rethrow so the broad catch below cannot swallow a cancellation.
                throw e
            } catch (e: Exception) {
                android.util.Log.w(TAG, "Could not read the picked attachment", e)
                return@withContext PickedAttachment.Unreadable(name)
            } ?: return@withContext PickedAttachment.Unreadable(name)

            PickedAttachment.Ready(
                // Decoded bytes, not base64: the encode happens once at the wire boundary rather
                // than being retained for the life of this screen. See [OutgoingAttachment].
                OutgoingAttachment(
                    name = name,
                    mimeType = resolver.getType(uri) ?: "application/octet-stream",
                    bytes = bytes,
                ),
            )
        }

        if (isFinishing || isDestroyed) return
        when (picked) {
            is PickedAttachment.Ready -> {
                attachments.add(picked.attachment)
                renderAttachmentChips()
            }
            is PickedAttachment.TooLarge ->
                Toast.makeText(this, getString(R.string.compose_attachments_too_large), Toast.LENGTH_LONG).show()
            is PickedAttachment.Unreadable ->
                Toast.makeText(this, getString(R.string.compose_attachment_unreadable, picked.name), Toast.LENGTH_SHORT).show()
        }
    }

    /** Outcome of reading one picked document — named rather than a nullable pair so the three
     *  cases stay distinguishable at the call site. */
    private sealed class PickedAttachment {
        data class Ready(val attachment: OutgoingAttachment) : PickedAttachment()
        data class TooLarge(val name: String) : PickedAttachment()
        data class Unreadable(val name: String) : PickedAttachment()
    }

    private fun renderAttachmentChips() {
        attachmentChips.removeAllViews()
        attachmentChips.visibility = if (attachments.isEmpty()) android.view.View.GONE else android.view.View.VISIBLE
        attachments.forEach { attachment ->
            val chip = Chip(this).apply {
                text = attachment.name
                isCloseIconVisible = true
                setOnCloseIconClickListener {
                    attachments.remove(attachment)
                    renderAttachmentChips()
                }
            }
            applyPillChipTheme(this, chip)
            attachmentChips.addView(chip)
        }
    }

    private fun sendEmail() {
        if (handoffBusy) return
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString().trim()
        val isBodyEmpty = bodyEditor.isEmptyFlow.value != false

        if (to.isBlank() || subject.isBlank() || isBodyEmpty) {
            Toast.makeText(this, R.string.compose_fill_all_fields, Toast.LENGTH_SHORT).show()
            return
        }

        sendMenuItem?.isEnabled = false

        bodyEditor.exportHtml { html ->
            // exportHtml's main-looper callback can fire after onDestroy shut ioExecutor down.
            if (isFinishing || isDestroyed) return@exportHtml
            val draft = MailDraft(
                to = to, cc = cc, bcc = bcc, subject = subject, body = html, mode = "html",
                attachments = attachments.toList(),
                sign = signChip.isChecked && signChip.visibility == View.VISIBLE,
                encrypt = encryptChip.isChecked && encryptChip.visibility == View.VISIBLE,
                // Never on for a first attempt. Only the post-409 re-send sets it, and only after
                // the user confirmed the dialog naming the addresses.
                allowPickupFallback = false,
            )
            sentDraft = draft
            // A client-custody account encrypts here, not on the relay; both chips unchecked is deliberate.
            if (clientSideAccount && (draft.sign || draft.encrypt)) {
                dispatchClientSend(draft)
            } else {
                dispatchSend(draft)
            }
        }
    }

    /** Sender built on IO (Keystore), crypto on Default (Bouncy Castle); the prompt hops to Main. */
    private fun dispatchClientSend(draft: MailDraft) {
        if (sendJob?.isActive == true) return
        sendMenuItem?.isEnabled = false
        sendJob = lifecycleScope.launch {
            val sender = withContext(Dispatchers.IO) { clientSender() }
            val outcome = if (sender == null) {
                null
            } else {
                withContext(Dispatchers.Default) { sender.send(draft, sign = draft.sign) }
            }
            // The unlock and the crypto can outlive the Activity: LockedActivity.onStart finishes
            // this screen outright if the app lock engages mid-send. Same guard dispatchSend uses.
            if (isFinishing || isDestroyed) return@launch
            if (outcome == null) {
                sendMenuItem?.isEnabled = true
                Toast.makeText(this@ComposeActivity, R.string.compose_pgp_not_paired, Toast.LENGTH_LONG).show()
                return@launch
            }
            renderClientSendOutcome(outcome)
        }
    }

    /** One branch per [ClientSendOutcome]; the rule itself is unit-tested in ClientEncryptedSenderTest. */
    private fun renderClientSendOutcome(outcome: ClientSendOutcome) {
        when (outcome) {
            is ClientSendOutcome.Sent -> {
                val message = outcome.warning.ifBlank { getString(R.string.compose_send_success) }
                val length = if (outcome.warning.isBlank()) Toast.LENGTH_SHORT else Toast.LENGTH_LONG
                Toast.makeText(this, message, length).show()
                sendSucceeded = true
                ComposeDraftCache.clear()
                finish()
            }
            // The user dismissed their own prompt. Not an error, and nothing to say — the screen
            // simply goes back to offering Send.
            is ClientSendOutcome.Cancelled -> sendMenuItem?.isEnabled = true
            is ClientSendOutcome.KeyChanged -> {
                sendMenuItem?.isEnabled = true
                warnKeyChanged(outcome.addresses)
            }
            is ClientSendOutcome.KeysMissing -> {
                sendMenuItem?.isEnabled = true
                explainMissingKeys(outcome.addresses)
            }
            else -> {
                sendMenuItem?.isEnabled = true
                Toast.makeText(this, clientSendMessage(outcome), Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun clientSendMessage(outcome: ClientSendOutcome): String = when (outcome) {
        is ClientSendOutcome.NotEnrolled -> getString(R.string.compose_pgp_not_enrolled)
        is ClientSendOutcome.NoSecureLockScreen -> getString(R.string.compose_pgp_no_lock_screen)
        is ClientSendOutcome.UnsealFailed -> getString(R.string.compose_pgp_unseal_failed, outcome.message)
        is ClientSendOutcome.NotClientProtected -> getString(R.string.compose_pgp_not_client_protected)
        is ClientSendOutcome.NoAccountAddress -> getString(R.string.compose_pgp_no_account_address)
        is ClientSendOutcome.TooManyRecipients -> outcome.message
        is ClientSendOutcome.ResolveFailed -> getString(R.string.compose_pgp_resolve_failed, outcome.message)
        is ClientSendOutcome.EncryptFailed -> getString(R.string.compose_pgp_encrypt_failed, outcome.message)
        is ClientSendOutcome.SendFailed -> outcome.outcome.userFacingMessage().orEmpty()
        else -> getString(R.string.compose_pgp_encrypt_failed, "")
    }

    /** Never merged into the missing-key case: rotation and interception look identical. */
    private fun warnKeyChanged(addresses: List<String>) {
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_pgp_key_changed_title)
            .setMessage(getString(R.string.compose_pgp_key_changed_body, addresses.joinToString(", ")))
            .setPositiveButton(android.R.string.ok, null)
            // FLAG_SECURE on the dialog's own window: the Activity's flag does not cover a separate window.
            .create()
            .showSecurely()
    }

    /** No pickup fallback here: the server-side one stores plaintext, which this exists to prevent. */
    private fun explainMissingKeys(addresses: List<String>) {
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_pgp_no_key_title)
            .setMessage(getString(R.string.compose_pgp_no_key_body, addresses.joinToString(", ")))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_pgp_no_key_webmail) { _, _ -> handOffToWebmail() }
            .create()
            .showSecurely()
    }

    /** Null when the device is not paired or bootstrap never answered, so no From is known. */
    private suspend fun clientSender(): ClientEncryptedSender? {
        val pairing = PushRuntime.graph(this).repository.pairingForAuthenticatedCall() ?: return null
        val deviceId = pairing.deviceId ?: return null
        val deviceSecret = pairing.deviceSecret ?: return null
        val address = pgpController.accountAddress()
        if (address.isBlank()) return null
        val resolveClient = RecipientResolveClient(callFactory = pinnedPairingCallFactory(this))
        return ClientEncryptedSender(
            opener = AndroidVaultOpener(this),
            resolver = { addresses -> resolveClient.resolve(pairing.serverUrl, deviceId, deviceSecret, addresses) },
            // Load-bearing: without it the outgoing key is only whatever the relay says it is.
            localKeys = RoomLocalSignerKeys(applicationContext),
            transport = { message -> MailRuntime.graph(this).repository.sendClientEncrypted(message) },
            accountAddress = address,
        )
    }

    /** Shared by the first attempt and the confirmed re-send, so the re-send cannot drift. */
    private fun dispatchSend(draft: MailDraft) {
        ioExecutor.execute {
            val outcome = MailRuntime.graph(this).repository.send(draft)
            runOnUiThread {
                // runOnUiThread still runs after finish(); an AlertDialog on a finishing Activity throws.
                if (isFinishing || isDestroyed) return@runOnUiThread
                when (outcome) {
                    is MailOutcome.Success -> {
                        val warning = outcome.value.warning
                        // The send already succeeded: surface the warning as a notice, never as a failure or a retry.
                        val message = warning.ifBlank { getString(R.string.compose_send_success) }
                        val length = if (warning.isBlank()) Toast.LENGTH_SHORT else Toast.LENGTH_LONG
                        Toast.makeText(this, message, length).show()
                        sendSucceeded = true
                        ComposeDraftCache.clear()
                        finish()
                    }
                    is MailOutcome.PickupFallbackNeeded -> {
                        sendMenuItem?.isEnabled = true
                        confirmPickupFallback(outcome.keylessRecipients)
                    }
                    is MailOutcome.ClientSideNeeded -> {
                        sendMenuItem?.isEnabled = true
                        handOffToWebmail()
                    }
                    else -> {
                        sendMenuItem?.isEnabled = true
                        Toast.makeText(this, outcome.userFacingMessage(), Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /** Nothing was delivered when this fires - the relay refuses before any SMTP. */
    private fun confirmPickupFallback(keylessRecipients: List<String>) {
        val draft = sentDraft ?: return
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_pickup_dialog_title)
            .setMessage(getString(R.string.compose_pickup_dialog_body, keylessRecipients.joinToString(", ")))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_pickup_dialog_confirm) { _, _ ->
                sendMenuItem?.isEnabled = false
                // The same draft, one flag flipped. Not rebuilt: no re-export of the editor HTML,
                // no re-encoded attachments, no second preflight.
                dispatchSend(draft.copy(allowPickupFallback = true))
            }
            // FLAG_SECURE: this dialog names recipients and gates storing plaintext on the server.
            .create()
            .showSecurely()
    }

    /** Resolve custody and the target before asking consent or exporting composition content. */
    private fun handOffToWebmail() {
        if (handoffBusy || sendJob?.isActive == true) return
        handoffBusy = true
        handoffAttempt++
        webmailChip.isEnabled = false
        sendMenuItem?.isEnabled = false
        handoffJob = lifecycleScope.launch {
            val serverUrl = withContext(Dispatchers.IO) {
                PushRuntime.graph(this@ComposeActivity).repository.pairingForAuthenticatedCall()?.serverUrl
            }
            val url = serverUrl?.let { webmailDraftsUrl(it) }
            if (isFinishing || isDestroyed) return@launch
            if (serverUrl == null || url == null) {
                finishHandoffAttempt()
                Toast.makeText(this@ComposeActivity, R.string.compose_handoff_no_webmail, Toast.LENGTH_LONG).show()
                return@launch
            }
            val mode = pgpController.draftHandoffMode()
            if (isFinishing || isDestroyed) return@launch
            if (mode == DraftHandoffMode.REFUSE) {
                finishHandoffAttempt()
                Toast.makeText(this@ComposeActivity, R.string.compose_handoff_refused, Toast.LENGTH_LONG).show()
            } else {
                confirmHandoff(serverUrl, url, mode)
            }
        }
    }

    private fun confirmHandoff(serverUrl: String, url: String, mode: DraftHandoffMode) {
        var accepted = false
        activeDialog = AlertDialog.Builder(this)
            .setTitle(R.string.compose_handoff_dialog_title)
            .setMessage(if (mode == DraftHandoffMode.ENCRYPT_AND_SAVE) R.string.compose_handoff_encrypted_body else R.string.compose_handoff_dialog_body)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.compose_handoff_dialog_confirm) { _, _ ->
                accepted = true
                if (mode == DraftHandoffMode.ENCRYPT_AND_SAVE) saveEncryptedHandoff(serverUrl, url)
                else {
                    finishHandoffAttempt()
                    if (!openWebmail(this, serverUrl, url)) {
                        Toast.makeText(this, R.string.compose_handoff_no_handler, Toast.LENGTH_LONG).show()
                    }
                }
            }
            .setOnDismissListener { if (!accepted) finishHandoffAttempt() }
            .create().showSecurely()
    }

    private fun saveEncryptedHandoff(serverUrl: String, url: String) {
        // A modal keeps edits from being lost while the captured draft is saved. The system
        // unlock prompt has its own window; cancellation leaves all composer fields in place.
        activeDialog = AlertDialog.Builder(this)
            .setMessage(R.string.compose_handoff_saving)
            .setNegativeButton(android.R.string.cancel) { _, _ ->
                handoffJob?.cancel()
                handoffOpener.cancel()
                finishHandoffAttempt()
            }
            .setCancelable(false)
            .create().showSecurely()
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString()
        val parts = attachments.toList()
        val attempt = handoffAttempt
        bodyEditor.exportHtml { html ->
            if (isFinishing || isDestroyed || !handoffBusy || attempt != handoffAttempt) return@exportHtml
            handoffJob = lifecycleScope.launch {
                // Re-probe after consent: a removed enrollment must never turn into a plaintext save.
                if (pgpController.draftHandoffMode() != DraftHandoffMode.ENCRYPT_AND_SAVE) {
                    completeDraftHandoff(DraftSaveOutcome.NotEnrolled) { false }
                    return@launch
                }
                val saver = ClientEncryptedDraftSaver(handoffOpener, pgpController.accountAddress()) {
                    MailRuntime.graph(this@ComposeActivity).repository.saveClientEncryptedDraft(it)
                }
                val result = saver.save(MailDraft(to, cc, bcc, subject, html, "html", parts))
                if (isFinishing || isDestroyed) return@launch
                completeDraftHandoff(result) { openWebmail(this@ComposeActivity, serverUrl, url) }
            }
        }
    }

    private fun finishHandoffAttempt() {
        handoffBusy = false
        handoffAttempt++
        webmailChip.isEnabled = true
        sendMenuItem?.isEnabled = !handoffOnlyAccount
    }

    /** Kept internal so device tests exercise the real failure/finish/cache behavior. */
    internal fun completeDraftHandoff(outcome: DraftSaveOutcome, openTarget: () -> Boolean) {
        activeDialog?.dismiss()
        activeDialog = null
        finishHandoffAttempt()
        if (outcome == DraftSaveOutcome.Saved) {
            if (openTarget()) {
                sendSucceeded = true
                ComposeDraftCache.clear()
                finish()
            } else Toast.makeText(this, R.string.compose_handoff_no_handler, Toast.LENGTH_LONG).show()
        } else if (outcome != DraftSaveOutcome.Cancelled) {
            val message = when (outcome) {
                DraftSaveOutcome.NoRecipient -> getString(R.string.compose_handoff_needs_recipient)
                is DraftSaveOutcome.SaveFailed -> outcome.outcome.userFacingMessage().orEmpty()
                else -> getString(R.string.compose_handoff_save_failed)
            }
            Toast.makeText(this, message, Toast.LENGTH_LONG).show()
        }
    }

    /** `onStop`, not `onDestroy`: [bodyEditor]'s HTML export is async and needs a live WebView. */
    override fun onStop() {
        super.onStop()
        mainHandler.removeCallbacks(bodyMirror)
        // onCreate bailed before assigning any view: there is no composition to stash, and
        // touching the lateinit fields below would throw.
        if (redirectedToUnlock) return
        if (isFinishing) {
            mirroredBodyHtml = ""
            ComposeDraftCache.clear()
            return
        }
        if (sendSucceeded) return
        val to = toInput.commaJoinedRecipients()
        val cc = ccInput.commaJoinedRecipients()
        val bcc = bccInput.commaJoinedRecipients()
        val subject = subjectField.text.toString()
        val currentAttachments = attachments.toList()
        val encrypt = encryptChip.isChecked
        val sign = signChip.isChecked
        val snapshot = CachedDraft(
            to = to,
            cc = cc,
            bcc = bcc,
            subject = subject,
            bodyHtml = mirroredBodyHtml,
            attachments = currentAttachments,
            encrypt = encrypt,
            sign = sign,
        )
        // Synchronously, from the mirror: everything after this line is best effort.
        ComposeDraftCache.save(snapshot)
        // The upgrade to the very last keystrokes, when the export still lands in time. Still
        // guarded: once destroyed, the replacement Activity has already taken the draft, and
        // re-saving would put a stale copy back for whoever opens Compose next.
        bodyEditor.exportHtml { html ->
            if (isDestroyed) return@exportHtml
            ComposeDraftCache.save(snapshot.copy(bodyHtml = html))
        }
    }

    override fun onDestroy() {
        if (handoffBusy) handoffOpener.cancel()
        super.onDestroy()
        // Both hold message plaintext, and neither is reachable from InMemoryPlaintext.clearAll().
        // Whatever the cache needed is already in it by now — onStop saved synchronously.
        mirroredBodyHtml = ""
        restoredDraftForTest = null
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
        // Dismiss rather than leave a shown AlertDialog referencing a destroyed Activity's window.
        activeDialog?.dismiss()
    }

    companion object {
        const val EXTRA_TO = "compose_to"
        const val EXTRA_SUBJECT = "compose_subject"
        const val EXTRA_BODY = "compose_body"

        /** A ready-made HTML quote, for Reply/Forward of an HTML message. Kept separate from
         *  [EXTRA_BODY] because that one is plain text and gets html-escaped on the way in. */
        const val EXTRA_BODY_HTML = "compose_body_html"

        private const val TAG = "ComposeActivity"

        /** The mirror's cadence, and so the ceiling on how much typing a sudden teardown costs. */
        private const val BODY_MIRROR_INTERVAL_MS = 2_000L

        /** Mirror of the backend maxMailAttachmentBytes (25 MB total decoded). Named in
         *  [MemoryBudget] rather than here, because what this admits decides what a send costs —
         *  see `SEND_SCENARIO_PEAK_BYTES`. */
        private const val MAX_ATTACHMENT_BYTES = MemoryBudget.OUTBOUND_ATTACHMENT_BYTES
        private const val MENU_SEND = 1
    }
}

/** Thrown by [readAtMost] so the caller can tell "this file is too big" apart from "this file could
 *  not be read", which a nullable return could not. */
internal class AttachmentTooLargeException : IOException("Attachment exceeds the remaining budget")

/** Copy buffer for [readAtMost]. Large enough that a 25 MB attachment is a few hundred reads, small
 *  enough that the refusal below happens long before the heap notices. */
private const val ATTACHMENT_COPY_BUFFER_BYTES = 64 * 1024

/** Reads [input] fully, or throws [AttachmentTooLargeException] past [limit] bytes. */
internal fun readAtMost(input: InputStream, limit: Long, expectedSize: Long = -1L): ByteArray {
    // Pre-sized to avoid ByteArrayOutputStream's doubling plus copy; clamped against over-reports.
    val initial = expectedSize.takeIf { it in 0..limit }?.toInt() ?: ATTACHMENT_COPY_BUFFER_BYTES
    val out = ByteArrayOutputStream(initial)
    val buffer = ByteArray(ATTACHMENT_COPY_BUFFER_BYTES)
    var total = 0L
    while (true) {
        val read = input.read(buffer)
        if (read == -1) return out.toByteArray()
        total += read
        if (total > limit) throw AttachmentTooLargeException()
        out.write(buffer, 0, read)
    }
}
