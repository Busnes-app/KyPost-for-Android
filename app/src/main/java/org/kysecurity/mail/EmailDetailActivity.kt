package org.kysecurity.mail

import android.content.Intent
import android.graphics.Color
import android.os.Bundle
import android.text.TextUtils
import android.view.View
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.ImageButton
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.mail.AttachmentInfo
import org.kysecurity.mail.mail.MailMessageBody
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.QuotedHtmlSanitizer
import org.kysecurity.mail.mail.addressFromHeader
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.pgp.AndroidVaultOpener
import org.kysecurity.mail.pgp.EncryptedMessageReader
import org.kysecurity.mail.pgp.PayloadSource
import org.kysecurity.mail.pgp.PgpMessageState
import org.kysecurity.mail.pgp.PgpPayloadClient
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.ReadOutcome
import org.kysecurity.mail.pgp.openWebmail
import org.kysecurity.mail.pgp.pgpMessageStateOf
import org.kysecurity.mail.pgp.rendersNothing
import org.kysecurity.mail.pgp.webmailMessageUrl
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import java.util.concurrent.Executors
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class EmailDetailActivity : LockedActivity() {

    // Two threads: a 25 MB attachment download used to block the body render behind it.
    private val ioExecutor = Executors.newFixedThreadPool(2)
    private lateinit var mailRepository: MailRepository
    private lateinit var actionButtons: List<ImageButton>

    /** The three buttons [applyReplyForwardAvailability] dims; explicit, not derived by index. */
    private lateinit var replyForwardButtons: List<ImageButton>

    /** Fails closed: [renderBody] may never report a state, so Reply must not start out live. */
    private var replyForwardState: PgpMessageState = PgpMessageState.CLIENT_PROTECTED
    private lateinit var divider: View
    private lateinit var webView: WebView
    private lateinit var plainTextScroll: View
    private lateinit var plainTextView: TextView
    private lateinit var lockedPlaceholder: android.widget.ImageView
    private lateinit var imagesBlockedBar: View
    private lateinit var btnShowImages: Button
    private lateinit var phishingBar: TextView
    private lateinit var pgpBar: View
    private lateinit var pgpText: TextView
    private lateinit var subjectView: TextView
    private lateinit var fromView: TextView
    private lateinit var btnOpenInWebmail: Button
    private lateinit var btnDecryptHere: Button
    private lateinit var btnRetryPayload: Button
    private var lastAppliedThemeName: String = ""
    private var lastRenderedHtml: String? = null

    /** Set when no webmail URL resolved; the notices below all assume a webmail fallback exists. */
    private var webmailUnavailable: Boolean = false

    /** Guards a second [attemptDecrypt] mid-flight from regressing the screen to the padlock. */
    private var decryptJob: Job? = null

    /** The message's real body, once the background fetch has answered. Reply/Forward quote this;
     *  see [quoteForReply] for why the 140-character preview was never an acceptable substitute. */
    private var fetchedBodyHtml: String? = null

    /** The relay's signature verdict, overwritten by the local one once a local decrypt finishes. */
    private var pgpSignatureState: PgpSignatureState = PgpSignatureState.NONE

    /** Only what the user actually opened is here - the honest limit of what Forward has in hand. */
    private val downloadedAttachments = linkedMapOf<Int, org.kysecurity.mail.mail.OutgoingAttachment>()

    /** Parts of the decrypted message, retained for the chips; zeroed on lock and destroy. Never
     *  copied into [downloadedAttachments]: Forward is blocked for CLIENT_PROTECTED and must stay so. */
    private var decryptedAttachments: List<org.kysecurity.mail.pgp.DecryptedAttachment> = emptyList()

    private fun dropDecryptedAttachments() {
        decryptedAttachments.forEach { java.util.Arrays.fill(it.bytes, 0) }
        decryptedAttachments = emptyList()
    }

    /** This message's attachment listing, once loaded — what Forward has to fetch. */
    private var attachmentInfos: List<AttachmentInfo> = emptyList()

    private var toRecipients: List<String> = emptyList()
    private var ccRecipients: List<String> = emptyList()

    /** A configuration-change recreate is not a new open. Reopening after the task was cleared is,
     *  and that path builds a fresh instance with no saved state, so it marks read again. */
    private var markReadSubmitted = false
    private var markReadSubmitCount = 0

    @androidx.annotation.VisibleForTesting
    internal fun markReadSubmitCountForTest(): Int = markReadSubmitCount

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        savedInstanceState?.let { state ->
            markReadSubmitted = state.getBoolean(STATE_MARK_READ_SUBMITTED, false)
            markReadSubmitCount = state.getInt(STATE_MARK_READ_COUNT, 0)
        }
        setContentView(R.layout.activity_email_detail)
        applyThemeToActivity(this)
        lastAppliedThemeName = getStoredThemeName(this)

        val root = findViewById<android.view.View>(R.id.emailDetailRoot)
        applyTopInsetWithHeader(this, root)

        val emailId = intent.getStringExtra("email_id").orEmpty()
        val emailFolder = intent.getStringExtra("email_folder") ?: "INBOX"
        val emailSubject = intent.getStringExtra("email_subject") ?: "No subject"
        val emailSender = intent.getStringExtra("email_sender") ?: "Unknown sender"
        val emailPreview = intent.getStringExtra("email_preview") ?: "No content"
        val emailBodyMode = intent.getStringExtra("email_body_mode").orEmpty()
        val hasAttachments = intent.getBooleanExtra("email_has_attachments", false)
        val pgpEncrypted = intent.getBooleanExtra("email_pgp_encrypted", false)
        // An unencrypted message was never going to become CLIENT_PROTECTED, so do not hold Reply.
        replyForwardState = initialReplyForwardState(pgpEncrypted)
        val pgpDecryptError = intent.getStringExtra("email_pgp_decrypt_error").orEmpty()
        pgpSignatureState = org.kysecurity.mail.pgp.pgpSignatureStateOf(
            pgpSigned = intent.getBooleanExtra("email_pgp_signed", false),
            pgpVerified = intent.getBooleanExtra("email_pgp_verified", false),
            pgpSignerFingerprint = intent.getStringExtra("email_pgp_signer_fingerprint").orEmpty(),
        )
        val phishingFlagged = intent.getBooleanExtra("email_suspicious", false)

        setTitle(R.string.email_title)

        subjectView = findViewById(R.id.emailSubject)
        fromView = findViewById(R.id.emailFrom)
        webView = findViewById(R.id.emailWebView)
        plainTextScroll = findViewById(R.id.emailPlainTextScroll)
        plainTextView = findViewById(R.id.emailPlainText)
        lockedPlaceholder = findViewById(R.id.emailLockedPlaceholder)
        divider = findViewById(R.id.emailDivider)
        imagesBlockedBar = findViewById(R.id.emailImagesBlockedBar)
        btnShowImages = findViewById(R.id.btnShowImages)
        phishingBar = findViewById(R.id.emailPhishingBar)
        // Advisory only: SAFE_LINK_SCHEMES already refuses these links regardless of the flag.
        phishingBar.visibility = if (phishingFlagged) View.VISIBLE else View.GONE
        pgpBar = findViewById(R.id.emailPgpBar)
        pgpText = findViewById(R.id.emailPgpText)
        btnOpenInWebmail = findViewById(R.id.btnOpenInWebmail)
        btnDecryptHere = findViewById(R.id.btnDecryptHere)
        btnRetryPayload = findViewById(R.id.btnRetryPayload)
        val loading = findViewById<ProgressBar>(R.id.emailBodyLoading)

        subjectView.text = emailSubject
        fromView.text = getString(R.string.email_from, emailSender)

        mailRepository = MailRuntime.graph(this).repository

        val actionArchive = findViewById<ImageButton>(R.id.actionArchive)
        val actionJunk = findViewById<ImageButton>(R.id.actionJunk)
        val actionDelete = findViewById<ImageButton>(R.id.actionDelete)
        val actionReply = findViewById<ImageButton>(R.id.actionReply)
        val actionReplyAll = findViewById<ImageButton>(R.id.actionReplyAll)
        val actionForward = findViewById<ImageButton>(R.id.actionForward)
        actionButtons = listOf(
            actionReply, actionReplyAll, actionForward,
            actionArchive, actionJunk, actionDelete,
        )
        replyForwardButtons = listOf(actionReply, actionReplyAll, actionForward)
        applyDetailChrome()

        // markRead stays non-reporting on purpose: it is incidental to opening the message, and a
        // toast about it would fire on top of the message the user just opened.
        if (!markReadSubmitted) {
            markReadSubmitted = true
            markReadSubmitCount++
            MailBackgroundExecutor.submit { mailRepository.markRead(emailId, emailFolder) }
        }

        actionArchive.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_archive), emailId) { it.archive(emailId, emailFolder) }
        }
        actionDelete.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_delete), emailId) { it.delete(emailId, emailFolder) }
        }
        actionJunk.setOnClickListener {
            runMailActionAndFinish(getString(R.string.action_junk), emailId) { it.spam(emailId, emailFolder) }
        }
        actionReply.setOnClickListener {
            // Not isEnabled = false: a disabled ImageButton never reaches performClick, so no Toast.
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = extractAddress(emailSender),
                    subject = withPrefix(emailSubject, "Re:"),
                    bodyHtml = quoteForReply(emailSender, quoted),
                )
            }
        }
        actionReplyAll.setOnClickListener {
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            val recipients = (listOf(extractAddress(emailSender)) + toRecipients.map(::extractAddress) + ccRecipients.map(::extractAddress))
                .distinct()
                .filter { it.isNotBlank() }
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = recipients.joinToString(", "),
                    subject = withPrefix(emailSubject, "Re:"),
                    bodyHtml = quoteForReply(emailSender, quoted),
                )
            }
        }
        actionForward.setOnClickListener {
            if (!mayReplyOrForward(replyForwardState)) {
                Toast.makeText(this, R.string.email_pgp_reply_disabled, Toast.LENGTH_LONG).show()
                return@setOnClickListener
            }
            forwardMessage(emailId, emailFolder, emailSender, emailSubject, emailPreview)
        }

        if (hasAttachments) {
            loadAttachments(emailId, emailFolder)
        }

        webView.settings.apply {
            javaScriptEnabled = false
            builtInZoomControls = true
            displayZoomControls = false
            useWideViewPort = true
            loadWithOverviewMode = true
            defaultTextEncodingName = "utf-8"
            // allowContentAccess defaults true, letting email markup reach this app's content:// providers.
            allowContentAccess = false
            allowFileAccess = false
            domStorageEnabled = false
            // blockNetworkImage covers only images; iframes, media, CSS and fonts fetch over the network too.
            blockNetworkLoads = true
        }
        // Without a WebViewClient, a link or <meta refresh> replaces this view in-app with no address bar.
        webView.webViewClient = object : WebViewClient() {
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest): Boolean {
                // Only a real tap: an <iframe src> or <meta refresh> fires this with hasGesture() false.
                if (!request.hasGesture()) return true
                val scheme = request.url.scheme?.lowercase()
                if (scheme !in SAFE_LINK_SCHEMES) {
                    Toast.makeText(
                        this@EmailDetailActivity,
                        R.string.email_link_blocked_scheme,
                        Toast.LENGTH_SHORT,
                    ).show()
                    return true
                }
                openExternally(request.url)
                return true
            }
        }
        btnShowImages.setOnClickListener {
            // blockNetworkImage, NOT blockNetworkLoads. Clearing the latter re-enables every remote
            // fetch — iframes, stylesheets, fonts, media, `url()` in CSS — which is not what a
            // button labelled "show images" asks for, and the sender chose all of them. The
            // narrower flag is only consulted while blockNetworkLoads is off, hence the order.
            webView.settings.blockNetworkLoads = false
            webView.settings.blockNetworkImage = false
            imagesBlockedBar.visibility = View.GONE
            // The images-stripped body, not the original: `blockExternalResources` has already
            // removed every non-image resource URL, so re-issuing it lets images through and
            // nothing else. WebView.reload() doesn't reliably re-fetch a loadDataWithBaseURL page.
            lastRenderedHtml?.let { html -> webView.loadDataWithBaseURL(null, html, "text/html", "utf-8", null) }
        }

        // runCatching: an uncaught throw on an executor thread is a process kill, on sender-chosen input.
        ioExecutor.execute {
            runCatching {
                renderBody(emailId, emailFolder, emailSender, emailPreview, emailBodyMode, pgpEncrypted, pgpDecryptError, loading)
            }
                .onFailure { error ->
                    android.util.Log.e(TAG, "Failed to render message body", error)
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        loading.visibility = android.view.View.GONE
                        Toast.makeText(this, R.string.email_body_render_failed, Toast.LENGTH_LONG).show()
                    }
                }
        }
    }

    /** Extracted from `onCreate` so the whole thing sits inside one `runCatching` on the executor. */
    private fun renderBody(
        emailId: String,
        emailFolder: String,
        emailSender: String,
        emailPreview: String,
        emailBodyMode: String,
        pgpEncrypted: Boolean,
        pgpDecryptError: String,
        loading: ProgressBar,
    ) {
        val outcome = mailRepository.fetchBody(emailId, emailFolder)
        val content = (outcome as? MailOutcome.Success)?.value
        // A failed fetch means "not cached", which is NOT the same as "the server sent no
        // body" — see MailRepository.fetchBody.
        val bodyUnavailable = outcome !is MailOutcome.Success
        // Routine since the inbox went bodies=0: the body is fetched on open, so any network
        // failure lands here rather than needing a missing cache row.
        val fetchFailure = bodyFetchFailureNotice(outcome)
        val pgpState = pgpMessageStateOf(pgpEncrypted, pgpDecryptError, content?.html, bodyUnavailable)
        // A client-protected message has no body to fall back to, and emailPreview is the
        // placeholder subject line — rendering it would look like the message content.
        val bodyMode = content?.bodyMode?.takeIf { it == "html" || it == "plain" } ?: emailBodyMode
        val bodyToRender = when (pgpState) {
            PgpMessageState.CLIENT_PROTECTED,
            PgpMessageState.DECRYPT_FAILED,
            PgpMessageState.BODY_UNAVAILABLE -> ""
            else -> content?.html?.takeIf { it.isNotBlank() }
                ?.let { emailBodyToHtml(it, bodyMode) }
                ?: if (mayFallBackToPreview(outcome)) emailBodyToHtml(emailPreview, "plain") else ""
        }
        // Computed from the same inputs the line above used, so the notice cannot claim the screen is
        // empty while something is on it, or stay silent while it is not.
        val nothingToRender = rendersNothing(pgpState, content?.html, emailPreview) || fetchFailure != null
        val palette = getStoredThemePalette(this)
        val monoFontFace = ibmPlexMonoFontFaceCss(this)
        val isDark = isDarkPalette(palette)
        val rendered = renderableBody(bodyToRender, palette, monoFontFace, isDark)
        val hasRemoteImages = rendered.hasRemoteImages
        val htmlToLoad = rendered.stripped
        val htmlWithImages = rendered.withImages
        // Off the main thread: pairingForAuthenticatedCall reads Keystore-backed prefs, i.e. disk I/O.
        val serverUrl = if (pgpState == PgpMessageState.CLIENT_PROTECTED) {
            PushRuntime.graph(this).repository.pairingForAuthenticatedCall()?.serverUrl
        } else {
            null
        }
        val webmailUrl = serverUrl?.let { webmailMessageUrl(it, emailFolder, emailId) }

        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            lastRenderedHtml = htmlWithImages
            // A local decrypt must never reach this property; not `bodyToRender`, which is blanked.
            fetchedBodyHtml = content?.html?.takeIf { pgpState != PgpMessageState.CLIENT_PROTECTED }
            val plainTextBody = content?.html?.takeIf { it.isNotBlank() }
                ?: emailPreview.takeIf { mayFallBackToPreview(outcome) }.orEmpty()
            val plainText = plainTextBody.takeIf { isPlainTextBody(it, bodyMode) }
            plainTextScroll.visibility = if (plainText != null) View.VISIBLE else View.GONE
            webView.visibility = if (plainText != null) View.GONE else View.VISIBLE
            plainTextView.text = plainText?.replace('\u00a0', ' ')?.let(::softWrapPlainText)
            if (plainText == null) {
                webView.loadDataWithBaseURL(null, htmlToLoad, "text/html", "utf-8", null)
            }
            loading.visibility = android.view.View.GONE
            imagesBlockedBar.visibility = if (hasRemoteImages) View.VISIBLE else View.GONE
            renderPgpBar(pgpState, pgpDecryptError, serverUrl, webmailUrl, nothingToRender, fetchFailure, emailFolder, emailId, emailSender)
            applyReplyForwardAvailability(pgpState)
            if (content != null) {
                toRecipients = content.toAddresses
                ccRecipients = content.ccAddresses
            }
        }
    }

    private fun forwardMessage(
        emailId: String,
        emailFolder: String,
        emailSender: String,
        emailSubject: String,
        emailPreview: String,
    ) {
        val missing = attachmentInfos.filter { it.index !in downloadedAttachments }
        if (missing.isEmpty()) {
            quotedBodyHtmlAsync(emailPreview) { quoted ->
                openCompose(
                    to = "",
                    subject = withPrefix(emailSubject, "Fwd:"),
                    bodyHtml = quoteForForward(emailSender, emailSubject, quoted),
                    attachments = orderedForwardAttachments(),
                )
            }
            return
        }

        Toast.makeText(this, R.string.forward_fetching_attachments, Toast.LENGTH_SHORT).show()
        ioExecutor.execute {
            val fetched = missing.map { info ->
                info.index to (mailRepository.downloadAttachment(emailId, emailFolder, info.index) as? MailOutcome.Success)?.value
            }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                var droppedForBudget = 0
                fetched.forEach { (index, downloaded) ->
                    if (downloaded != null && !rememberForForwarding(index, downloaded)) droppedForBudget++
                }
                val failed = fetched.count { it.second == null }
                if (failed > 0) {
                    // Say so rather than quietly forwarding a message with attachments missing.
                    Toast.makeText(
                        this,
                        resources.getQuantityString(R.plurals.forward_attachments_failed, failed, failed),
                        Toast.LENGTH_LONG,
                    ).show()
                }
                if (droppedForBudget > 0) {
                    // Distinct from a failed download: these were fetched fine and are too large to
                    // carry. Silence here would forward a message minus attachments it appears to have.
                    Toast.makeText(
                        this,
                        resources.getQuantityString(
                            R.plurals.forward_attachments_too_large,
                            droppedForBudget,
                            droppedForBudget,
                        ),
                        Toast.LENGTH_LONG,
                    ).show()
                }
                // Same sanitize-or-escape hop as the branch above; never interpolate raw sender HTML.
                quotedBodyHtmlAsync(emailPreview) { quoted ->
                    openCompose(
                        to = "",
                        subject = withPrefix(emailSubject, "Fwd:"),
                        bodyHtml = quoteForForward(emailSender, emailSubject, quoted),
                        attachments = orderedForwardAttachments(),
                    )
                }
            }
        }
    }

    /** Attachment order is the sender's, not the order the user happened to tap them in. */
    private fun orderedForwardAttachments(): List<org.kysecurity.mail.mail.OutgoingAttachment> =
        attachmentInfos.mapNotNull { downloadedAttachments[it.index] }
            .ifEmpty { downloadedAttachments.values.toList() }

    /** Bounded by [MemoryBudget.FORWARD_ATTACHMENT_BYTES]. Refuses rather than evicts: dropping an
     *  earlier attachment to make room would forward a message that silently lost one.
     *  @return false when this attachment did not fit and was not retained. */
    private fun rememberForForwarding(index: Int, downloaded: org.kysecurity.mail.mail.DownloadedAttachment): Boolean {
        if (downloadedAttachments.containsKey(index)) return true
        val held = downloadedAttachments.values.sumOf { it.size.toLong() }
        if (held + downloaded.bytes.size > MemoryBudget.FORWARD_ATTACHMENT_BYTES) {
            android.util.Log.w(
                TAG,
                "Not retaining ${downloaded.bytes.size} more bytes for forwarding; already holding $held",
            )
            return false
        }
        downloadedAttachments[index] = org.kysecurity.mail.mail.OutgoingAttachment(
            name = downloaded.name,
            mimeType = downloaded.mimeType,
            bytes = downloaded.bytes,
        )
        return true
    }

    /** [serverUrl] is passed beside [webmailUrl] so both are provably from the same render pass. */
    private fun renderPgpBar(
        state: PgpMessageState,
        pgpDecryptError: String,
        serverUrl: String?,
        webmailUrl: String?,
        /** Decided by [rendersNothing] in the same render pass that chose the body, so this cannot
         *  disagree with what was actually put on screen. */
        nothingToRender: Boolean,
        /** The body fetch's own failure, or null. Takes precedence over [R.string.email_no_content]
         *  below: that string claims the server answered and had nothing, which a failed fetch has
         *  not established — and the two call for different responses from the user. */
        fetchFailure: String?,
        /** Only needed to kick off [attemptDecrypt] from the CLIENT_PROTECTED branch below. */
        mailbox: String,
        messageId: String,
        sender: String,
    ) {
        // A readable message can still be signed by someone other than its claimed sender.
        val signatureNotice = signatureNoticeFor(pgpSignatureState)

        if (state == PgpMessageState.NONE) {
            // An encrypted message the server never warmed arrives with pgpEncrypted false and no body.
            val notice = emptyBodyNotice(
                signatureNotice,
                fetchFailure,
                getString(R.string.email_no_content),
                nothingToRender,
            )
            pgpBar.visibility = if (notice == null) View.GONE else View.VISIBLE
            btnOpenInWebmail.visibility = View.GONE
            pgpText.text = notice.orEmpty()
            pgpText.visibility = if (notice == null) View.GONE else View.VISIBLE
            return
        }
        pgpBar.visibility = View.VISIBLE
        btnOpenInWebmail.visibility = View.GONE

        when (state) {
            PgpMessageState.DECRYPT_FAILED ->
                pgpText.text = getString(R.string.email_pgp_decrypt_failed, pgpDecryptError)
            PgpMessageState.DECRYPTED_BY_SERVER ->
                pgpText.text = getString(R.string.email_pgp_decrypted_by_server)
            PgpMessageState.CLIENT_PROTECTED -> {
                webmailUnavailable = serverUrl == null || webmailUrl == null
                // Deferred to renderReadOutcome: otherwise the fallback flashes before the decrypt resolves.
                if (serverUrl != null && webmailUrl != null) {
                    btnOpenInWebmail.setOnClickListener {
                        // The installed PWA, else the real browser, in that app's own task. See WebmailTab.
                        if (!openWebmail(this, serverUrl, webmailUrl)) {
                            Toast.makeText(this, R.string.email_pgp_no_handler, Toast.LENGTH_LONG).show()
                        }
                    }
                }
                btnOpenInWebmail.visibility = View.GONE
                // Actionable buttons only; the signature badge is rendered at the end of this function.
                pgpText.text = ""
                // Explicit taps always may prompt; only the automatic attempt below is silent when
                // the key is not held.
                btnDecryptHere.setOnClickListener {
                    attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = true)
                }
                btnRetryPayload.setOnClickListener {
                    attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = true)
                }
                // Automatic only when the key is already held: unlockIfNeeded = false means this
                // never raises a biometric sheet on a message the user simply opened.
                attemptDecrypt(mailbox, messageId, sender, unlockIfNeeded = false)
            }
            PgpMessageState.BODY_UNAVAILABLE ->
                pgpText.text = getString(R.string.email_pgp_body_unavailable)
            PgpMessageState.NONE -> Unit
        }

        // Prepended, not appended: a signature that does not match the sender is the more urgent of
        // the two facts, and it should not sit below a paragraph about decryption.
        if (signatureNotice != null) {
            val current = pgpText.text.toString()
            pgpText.text = if (current.isBlank()) signatureNotice else signatureNotice + "\n\n" + current
        }
        pgpText.visibility = if (pgpText.text.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    /** Not `isEnabled = false`: a disabled view never reaches performClick, so the Toast would die. */
    private fun applyReplyForwardAvailability(pgpState: PgpMessageState) {
        replyForwardState = pgpState
        if (mayReplyOrForward(pgpState)) return
        val notice = getString(R.string.email_pgp_reply_disabled)
        replyForwardButtons.forEach { button ->
            button.alpha = 0.4f
            button.contentDescription = notice
        }
    }

    /** Shared by [renderPgpBar] and [renderReadOutcome] so the wording cannot drift. */
    private fun signatureNoticeFor(state: PgpSignatureState): String? = when (state) {
        PgpSignatureState.UNSIGNED -> "⬜ " + getString(R.string.email_pgp_signature_unsigned)
        PgpSignatureState.VERIFIED_CONFIRMED -> "✅ " + getString(R.string.email_pgp_signature_confirmed)
        PgpSignatureState.VERIFIED_SEEN_BEFORE -> "🟢 " + getString(R.string.email_pgp_signature_seen_before)
        PgpSignatureState.SIGNER_UNKNOWN -> "⬜ " + getString(R.string.email_pgp_signature_signer_unknown)
        PgpSignatureState.INVALID -> "⚠️ " + getString(R.string.email_pgp_signature_invalid)
        PgpSignatureState.KEY_CHANGED -> "⚠️ " + getString(R.string.email_pgp_signature_key_changed)
        PgpSignatureState.NONE -> null
    }

    /** Built lazily: constructing it needs the pairing credential, which is a disk read — so this
     *  itself must only ever run off Main; see [attemptDecrypt]'s `Dispatchers.IO` hop. */
    private suspend fun encryptedReader(): EncryptedMessageReader? {
        val pairing = PushRuntime.graph(this).repository.pairingForAuthenticatedCall() ?: return null
        val deviceId = pairing.deviceId ?: return null
        val deviceSecret = pairing.deviceSecret ?: return null
        val client = PgpPayloadClient(callFactory = pinnedPairingCallFactory(this))
        return EncryptedMessageReader(
            // No wrapper: AndroidVaultOpener.open() owns its own dispatching. See VaultOpenerAndroid.kt.
            opener = AndroidVaultOpener(this@EmailDetailActivity),
            payloads = object : PayloadSource {
                override suspend fun fetch(mailbox: String, messageId: String) =
                    client.fetch(pairing.serverUrl, deviceId, deviceSecret, mailbox, messageId)
            },
            // Load-bearing: without it the signature verdict is only whatever the relay says it is.
            localSignerKeys = org.kysecurity.mail.pgp.RoomLocalSignerKeys(applicationContext),
        )
    }

    /** [EncryptedMessageReader.read] is Android-free: dispatching it off Main is the caller's job. */
    private fun attemptDecrypt(mailbox: String, messageId: String, sender: String, unlockIfNeeded: Boolean) {
        if (decryptJob?.isActive == true) return
        btnDecryptHere.isEnabled = false
        btnRetryPayload.isEnabled = false
        decryptJob = lifecycleScope.launch {
            val reader = withContext(Dispatchers.IO) { encryptedReader() }
            if (reader == null) {
                renderReadOutcome(ReadOutcome.NotEnrolled)
                return@launch
            }
            val outcome = withContext(Dispatchers.Default) {
                reader.read(mailbox, messageId, sender, unlockIfNeeded)
            }
            renderReadOutcome(outcome)
        }
    }

    private fun renderReadOutcome(outcome: ReadOutcome) {
        if (isFinishing || isDestroyed) return
        btnDecryptHere.visibility = View.GONE
        btnDecryptHere.isEnabled = true
        btnRetryPayload.visibility = View.GONE
        btnRetryPayload.isEnabled = true

        when (outcome) {
            is ReadOutcome.Decrypted -> {
                // The body goes to the WebView and NOWHERE else: not Room, and not fetchedBodyHtml.
                lockedPlaceholder.visibility = View.GONE
                val plainText = outcome.body.plain?.takeIf {
                    isPlainTextBody(it, outcome.body.bodyMode)
                }
                plainTextScroll.visibility = if (plainText != null) View.VISIBLE else View.GONE
                webView.visibility = if (plainText != null) View.GONE else View.VISIBLE
                plainTextView.text = plainText?.replace('\u00a0', ' ')?.let(::softWrapPlainText)
                val rawHtml = org.kysecurity.mail.pgp.inlineCidImages(
                    emailBodyToHtml(outcome.body.html ?: plainText.orEmpty(), outcome.body.bodyMode),
                    outcome.body.attachments,
                )
                // The same dark-theme override every other body gets, or a sender's colors go black-on-black.
                val palette = getStoredThemePalette(this)
                // Through the SAME helper renderBody uses. This path had its own copy of the
                // stripping decision, with a different guard, on a WebView whose blockNetworkLoads
                // is mutable and shared with the envelope render above it. Two copies of one
                // security control had already drifted once.
                // keepInlineDataImages: only the decrypted body may keep raster data: images, because
                // only here are they bounded by INLINE_IMAGE_BYTES (see Task 3's ruling).
                val rendered = renderableBody(rawHtml, palette, ibmPlexMonoFontFaceCss(this), isDarkPalette(palette), keepInlineDataImages = true)
                if (plainText == null) {
                    lastRenderedHtml = rendered.withImages
                    webView.loadDataWithBaseURL(null, rendered.stripped, "text/html", "utf-8", null)
                }
                imagesBlockedBar.visibility = if (plainText == null && rendered.hasRemoteImages) View.VISIBLE else View.GONE
                // The real subject from the encrypted part's protected headers; the envelope one is a placeholder.
                outcome.body.protectedSubject?.takeIf { it.isNotBlank() }?.let { subjectView.text = it }
                // The verdict actually safe to display — see displaySignatureVerdict's KDoc for why
                // this can differ from outcome.signature itself.
                val verdict = displaySignatureVerdict(outcome)
                pgpSignatureState = verdict
                // Show the mailbox the verdict is ABOUT, not the sender-written header beside it.
                if (verdict != PgpSignatureState.NONE) {
                    fromView.text = getString(R.string.email_from, outcome.resolvedSender)
                }
                val omission = decryptedAttachmentNotice(outcome.body.attachmentsOmitted)
                    ?.let { getString(it) }
                val notice = listOfNotNull(signatureNoticeFor(verdict), omission).joinToString("\n\n").ifBlank { null }
                if (notice != null) {
                    pgpBar.visibility = View.VISIBLE
                    pgpText.text = notice
                    pgpText.visibility = View.VISIBLE
                } else {
                    pgpBar.visibility = View.GONE
                    pgpText.text = ""
                    pgpText.visibility = View.GONE
                }
                btnOpenInWebmail.visibility = View.GONE
                dropDecryptedAttachments()
                decryptedAttachments = outcome.body.attachments
                renderDecryptedAttachments(outcome.body.attachmentsOmitted)
            }
            // The decrypt can still be retried here and the user is the missing input, so offer
            // it rather than the webmail fallback. Cancelled is silent on purpose: the user
            // dismissed a sheet they raised, and a toast would be noise about their own action.
            ReadOutcome.NeedsUnlock,
            ReadOutcome.Cancelled,
            -> {
                showLocked("")
                btnDecryptHere.visibility = View.VISIBLE
                btnOpenInWebmail.visibility = View.GONE
            }
            // Every remaining outcome means "this device cannot open this message", and they share
            // the same furniture: the padlock plus the webmail fallback when one resolved. They do
            // NOT share a sentence — `readFailureNotice` gives each its own, because a decrypt that
            // failed on this device and a message the server refused are different problems and a
            // wordless padlock told the reader neither. Listed rather than collapsed to `else` so
            // the compiler still forces a decision when a new outcome is added; whether Retry is
            // offered is decided by `showsRetryButton` below, not here.
            ReadOutcome.NotEnrolled,
            ReadOutcome.NoSecureLockScreen,
            ReadOutcome.TooLarge,
            ReadOutcome.NotClientProtected,
            ReadOutcome.NoEncryptedContent,
            ReadOutcome.NoReadableContent,
            is ReadOutcome.UnsealFailed,
            is ReadOutcome.FetchFailed,
            is ReadOutcome.DecryptFailed,
            -> {
                showLocked(noticeTextFor(outcome))
                btnOpenInWebmail.visibility = if (webmailUnavailable) View.GONE else View.VISIBLE
            }
        }
        // Routed through the pure decision below so NoEncryptedContent cannot drift into offering Retry.
        btnRetryPayload.visibility = if (showsRetryButton(outcome)) View.VISIBLE else View.GONE
    }

    /** Resolves [readFailureNotice] against resources; empty for an outcome that has no sentence. */
    private fun noticeTextFor(outcome: ReadOutcome): String {
        val (resId, detail) = readFailureNotice(outcome) ?: return ""
        return if (detail == null) getString(resId) else getString(resId, detail)
    }

    /** Padlock and webmail button appear together, except when [webmailUnavailable]. */
    private fun showLocked(notice: String) {
        webView.visibility = View.GONE
        plainTextScroll.visibility = View.GONE
        // Otherwise the decrypted plaintext DOM from an earlier Decrypted render lives on behind
        // the padlock, unloaded but still present.
        webView.loadUrl("about:blank")
        dropDecryptedAttachments()
        findViewById<ChipGroup>(R.id.emailAttachmentChips).removeAllViews()
        lockedPlaceholder.visibility = View.VISIBLE
        pgpBar.visibility = View.VISIBLE
        val body = if (webmailUnavailable) {
            if (notice.isBlank()) getString(R.string.email_pgp_no_webmail) else notice + "\n" + getString(R.string.email_pgp_no_webmail)
        } else {
            notice
        }
        // Prepended, not appended — same reasoning as renderPgpBar and the Decrypted branch above: a
        // signature that does not match the sender outranks a readability notice.
        val sig = signatureNoticeFor(pgpSignatureState)
        val bodyPart = body.takeIf { it.isNotBlank() }
        pgpText.text = listOfNotNull(sig, bodyPart).joinToString("\n\n")
        pgpText.visibility = if (pgpText.text.isNullOrBlank()) View.GONE else View.VISIBLE
    }

    private fun loadAttachments(emailId: String, emailFolder: String) {
        ioExecutor.execute {
            val outcome = mailRepository.listAttachments(emailId, emailFolder)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                val infos = (outcome as? MailOutcome.Success)?.value.orEmpty()
                renderAttachments(emailId, emailFolder, infos)
            }
        }
    }

    private fun renderAttachments(emailId: String, emailFolder: String, infos: List<AttachmentInfo>) {
        attachmentInfos = infos
        val label = findViewById<TextView>(R.id.emailAttachmentsLabel)
        val chips = findViewById<ChipGroup>(R.id.emailAttachmentChips)
        chips.removeAllViews()
        if (infos.isEmpty()) {
            label.visibility = View.GONE
            chips.visibility = View.GONE
            return
        }
        label.visibility = View.VISIBLE
        chips.visibility = View.VISIBLE
        // Read once, not once per chip: this opens a SharedPreferences file, and it was inside
        // the loop.
        val protectionEnabled = org.kysecurity.mail.security.SecurityRuntime
            .graph(this).hostileLocationSettings.isEnabled()
        val saveOffered = org.kysecurity.mail.security.attachmentSaveOffered(protectionEnabled)
        infos.forEach { info ->
            val chip = Chip(this).apply {
                text = getString(R.string.attachment_chip_label, info.name)
                // A tap views; saving outside the sandbox is a second, confirmed gesture.
                setOnClickListener {
                    downloadAttachment(emailId, emailFolder, info, org.kysecurity.mail.security.AttachmentAction.VIEW_EPHEMERAL)
                }
                if (saveOffered) {
                    setOnLongClickListener {
                        confirmSaveToDownloads(emailId, emailFolder, info)
                        true
                    }
                }
            }
            applyPillChipTheme(this, chip)
            chips.addView(chip)
        }
        label.text = getString(
            if (saveOffered) R.string.email_attachments_label_tap_to_view_hold_to_save
            else R.string.email_attachments_label_tap_to_view,
        )
    }

    /** Chips for parts that came out of the ciphertext. Tap opens through the ephemeral provider;
     *  hold saves after the same confirmation the server-listed chips use. */
    private fun renderDecryptedAttachments(omitted: Boolean) {
        val label = findViewById<TextView>(R.id.emailAttachmentsLabel)
        val chips = findViewById<ChipGroup>(R.id.emailAttachmentChips)
        chips.removeAllViews()
        if (decryptedAttachments.isEmpty()) {
            label.visibility = View.GONE
            chips.visibility = View.GONE
            return
        }
        label.visibility = View.VISIBLE
        chips.visibility = View.VISIBLE
        val protectionEnabled = org.kysecurity.mail.security.SecurityRuntime
            .graph(this).hostileLocationSettings.isEnabled()
        val saveOffered = org.kysecurity.mail.security.attachmentSaveOffered(protectionEnabled)
        decryptedAttachments.forEach { part ->
            val chip = Chip(this).apply {
                text = getString(R.string.attachment_chip_label, part.name)
                setOnClickListener {
                    // register() takes ownership and zeroes; the chip must survive a second tap.
                    viewAttachmentEphemerally(
                        org.kysecurity.mail.mail.DownloadedAttachment(part.name, part.mimeType, part.bytes.copyOf()),
                    )
                }
                if (saveOffered) {
                    setOnLongClickListener {
                        androidx.appcompat.app.AlertDialog.Builder(this@EmailDetailActivity)
                            .setTitle(R.string.attachment_save_confirm_title)
                            .setMessage(getString(R.string.attachment_save_confirm_message, part.name))
                            .setPositiveButton(R.string.attachment_save_confirm_positive) { _, _ ->
                                ioExecutor.execute {
                                    val saved = org.kysecurity.mail.security.saveAttachmentToDownloads(
                                        this@EmailDetailActivity,
                                        safeFileName(part.name, part.mimeType),
                                        part.mimeType,
                                        part.bytes,
                                    )
                                    runOnUiThread {
                                        if (isFinishing || isDestroyed) return@runOnUiThread
                                        val id = if (saved) R.string.attachment_saved else R.string.attachment_save_failed
                                        Toast.makeText(this@EmailDetailActivity, getString(id, part.name), Toast.LENGTH_LONG).show()
                                    }
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                            .create()
                            .showSecurely()
                        true
                    }
                }
            }
            applyPillChipTheme(this, chip)
            chips.addView(chip)
        }
        label.text = getString(
            if (saveOffered) R.string.email_pgp_attachments_label_hold_to_save
            else R.string.email_pgp_attachments_label,
        )
    }

    /** Everything except the Toast and the chooser runs on [ioExecutor]; the payload can be 25 MB. */
    private fun downloadAttachment(
        emailId: String,
        emailFolder: String,
        info: AttachmentInfo,
        action: org.kysecurity.mail.security.AttachmentAction,
    ) {
        val loadingMessage = if (action == org.kysecurity.mail.security.AttachmentAction.VIEW_EPHEMERAL) {
            getString(R.string.attachment_opening, info.name)
        } else {
            getString(R.string.attachment_downloading, info.name)
        }
        Toast.makeText(this, loadingMessage, Toast.LENGTH_SHORT).show()
        ioExecutor.execute {
            val outcome = mailRepository.downloadAttachment(emailId, emailFolder, info.index)
            val downloaded = (outcome as? MailOutcome.Success)?.value
            if (downloaded == null) {
                val message = outcome.userFacingMessage() ?: getString(R.string.attachment_save_failed, info.name)
                runOnUiThread {
                    if (!isFinishing && !isDestroyed) Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                }
                return@execute
            }
            when (action) {
                // Not cached for forwarding: base64 makes an immutable String, and a String cannot be zeroed.
                org.kysecurity.mail.security.AttachmentAction.VIEW_EPHEMERAL -> runOnUiThread {
                    // Registering and launching the chooser is cheap and needs an Activity context.
                    if (!isFinishing && !isDestroyed) viewAttachmentEphemerally(downloaded)
                }
                org.kysecurity.mail.security.AttachmentAction.SAVE_TO_DOWNLOADS -> {
                    val saved = org.kysecurity.mail.security.saveAttachmentToDownloads(
                        this, downloaded.name, downloaded.mimeType, downloaded.bytes,
                    )
                    val message = if (saved) getString(R.string.attachment_saved, info.name) else getString(R.string.attachment_save_failed, info.name)
                    runOnUiThread {
                        if (isFinishing || isDestroyed) return@runOnUiThread
                        // On Main, like every other touch of downloadedAttachments: a plain
                        // LinkedHashMap written from this pool AND from the forward path on Main
                        // is a data race, not merely an ordering question.
                        rememberForForwarding(info.index, downloaded)
                        Toast.makeText(this, message, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /** Saving puts decrypted mail outside the sandbox, where no wipe step reaches it directly. */
    private fun confirmSaveToDownloads(emailId: String, emailFolder: String, info: AttachmentInfo) {
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(R.string.attachment_save_confirm_title)
            .setMessage(getString(R.string.attachment_save_confirm_message, info.name))
            .setPositiveButton(R.string.attachment_save_confirm_positive) { _, _ ->
                downloadAttachment(emailId, emailFolder, info, org.kysecurity.mail.security.AttachmentAction.SAVE_TO_DOWNLOADS)
            }
            .setNegativeButton(android.R.string.cancel, null)
            .create()
            .showSecurely()
    }

    /** Hostile Location Protection path: hands the bytes to [org.kysecurity.mail.security.EphemeralAttachmentBytes]
     *  (never written to disk) and launches a viewer via ACTION_VIEW — nothing is saved anywhere. */
    private fun viewAttachmentEphemerally(downloaded: org.kysecurity.mail.mail.DownloadedAttachment) {
        val mimeType = safeMimeType(downloaded.mimeType, downloaded.name)
        // Null when the held-plaintext ceiling is reached — say so rather than launching a chooser
        // for a URI that will fail to open. See EphemeralAttachmentBytes.register.
        val uri = org.kysecurity.mail.security.EphemeralAttachmentBytes
            .register(downloaded.bytes, mimeType, downloaded.name)
            ?: run {
                Toast.makeText(this, R.string.attachment_too_many_open, Toast.LENGTH_LONG).show()
                return
            }
        val view = Intent(Intent.ACTION_VIEW).apply {
            setDataAndType(uri, mimeType)
            addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        }
        // Always show the chooser, so no app can become a silent default for the attachment type.
        val chooser = Intent.createChooser(view, getString(R.string.attachment_open_with))
            .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
        runCatching { startActivity(chooser) }.onFailure {
            Toast.makeText(this, getString(R.string.attachment_save_failed, downloaded.name), Toast.LENGTH_LONG).show()
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return

        val currentTheme = getStoredThemeName(this)
        if (currentTheme != lastAppliedThemeName) {
            recreate()
            return
        }

        applyThemeToActivity(this)
        applyDetailChrome()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        outState.putBoolean(STATE_MARK_READ_SUBMITTED, markReadSubmitted)
        outState.putInt(STATE_MARK_READ_COUNT, markReadSubmitCount)
    }

    private fun applyDetailChrome() {
        val palette = getStoredThemePalette(this)
        divider.setBackgroundColor(Color.parseColor(palette.line))
        webView.setBackgroundColor(Color.parseColor(palette.bg))
        // Same warning-callout treatment ComposeActivity's keyless-recipient
        // notice uses, so a security warning looks the same everywhere.
        applyWarningCalloutTheme(this, phishingBar)
        actionButtons.forEach { applyIconButtonTheme(this, it) }
    }

    private fun runMailActionAndFinish(actionLabel: String, emailId: String, action: (MailRepository) -> MailOutcome<Unit>) {
        Toast.makeText(this, actionLabel, Toast.LENGTH_SHORT).show()
        // Reporting, not fire-and-forget: the row is removed optimistically, so a failure the user
        // never hears about reads as "it worked" until the message reappears on the next resync.
        MailBackgroundExecutor.submitReporting(this, actionLabel) { action(mailRepository) }
        // Tell InboxActivity which row to drop, or its onStart refresh races the in-flight mutation.
        setResult(RESULT_OK, Intent().putExtra(EXTRA_REMOVED_EMAIL_ID, emailId))
        finish()
    }

    private fun openCompose(
        to: String,
        subject: String,
        bodyHtml: String,
        attachments: List<org.kysecurity.mail.mail.OutgoingAttachment> = emptyList(),
    ) {
        val intent = Intent(this, ComposeActivity::class.java)
        intent.putExtra(ComposeActivity.EXTRA_TO, to)
        intent.putExtra(ComposeActivity.EXTRA_SUBJECT, subject)
        intent.putExtra(ComposeActivity.EXTRA_BODY_HTML, bodyHtml)
        // Process-scoped handoff, not an Intent extra: 25 MB is far past Binder's ~1 MB limit.
        if (attachments.isNotEmpty()) ForwardAttachmentHandoff.put(attachments)
        startActivity(intent)
    }

    /** CATEGORY_BROWSABLE + NEW_TASK: an email link must not reach non-browsable activities. */
    private fun openExternally(uri: android.net.Uri) {
        val intent = Intent(Intent.ACTION_VIEW, uri)
            .addCategory(Intent.CATEGORY_BROWSABLE)
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
        runCatching { startActivity(intent) }
            .onFailure { Toast.makeText(this, R.string.email_link_no_handler, Toast.LENGTH_SHORT).show() }
    }

    /** Sanitizes the quoted original off the UI thread; `Jsoup.clean` is quadratic in nesting. */
    private fun quotedBodyHtmlAsync(preview: String, then: (String) -> Unit) {
        val body = fetchedBodyHtml?.takeIf { it.isNotBlank() }
        if (body == null || body.length > QUOTE_SANITIZE_MAX_LENGTH) {
            then(TextUtils.htmlEncode(preview))
            return
        }
        ioExecutor.execute {
            val sanitized = runCatching { QuotedHtmlSanitizer.sanitize(body) }
                .getOrElse { TextUtils.htmlEncode(preview) }
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                then(sanitized)
            }
        }
    }

    private fun quoteForReply(sender: String, quoted: String): String =
        "<br><br><div>${TextUtils.htmlEncode(sender)} wrote:</div>" +
            "<blockquote style=\"margin:0 0 0 0.8ex;border-left:1px solid #ccc;padding-left:1ex\">" +
            quoted +
            "</blockquote>"

    private fun quoteForForward(sender: String, subject: String, quoted: String): String =
        "<br><br><div>---------- Forwarded message ----------</div>" +
            "<div>From: ${TextUtils.htmlEncode(sender)}</div>" +
            "<div>Subject: ${TextUtils.htmlEncode(subject)}</div><br>" +
            quoted

    private fun withPrefix(subject: String, prefix: String): String {
        return if (subject.trim().startsWith(prefix, ignoreCase = true)) subject else "$prefix $subject"
    }

    // Delegates to mail/AddressText.kt: a display name must never win over the real angle-addr.
    private fun extractAddress(raw: String): String = addressFromHeader(raw)

    override fun onDestroy() {
        super.onDestroy()
        dropDecryptedAttachments()
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
    }

    companion object {
        private const val TAG = "EmailDetailActivity"

        const val EXTRA_REMOVED_EMAIL_ID = "removed_email_id"

        private const val STATE_MARK_READ_SUBMITTED = "mark_read_submitted"
        private const val STATE_MARK_READ_COUNT = "mark_read_count"

        /** `intent:`, `file:`, `content:` and any app's custom scheme are refused. */
        private val SAFE_LINK_SCHEMES = setOf("http", "https", "mailto", "tel")

        /** Caps the quote sanitizer only: `Jsoup.clean` is quadratic in nesting depth, so a
         *  sender-chosen body past this size falls back to the escaped preview. NOT a
         *  remote-content bound — [renderableBody] strips unconditionally and at any size. */
        private const val QUOTE_SANITIZE_MAX_LENGTH = 512 * 1024
    }
}

/** A body that has already been through [blockExternalResources], both ways.
 *
 *  [hasRemoteImages] is EXACT, not a guess: it is true when keeping images actually changes the
 *  output, which is the only definition that cannot disagree with what the two strings contain. */
internal class RenderableBody(
    val stripped: String,
    val withImages: String,
    val hasRemoteImages: Boolean,
)

/** Strips remote resources UNCONDITIONALLY, and is the single place that decides how a body is
 *  rendered.
 *
 *  Both render paths in this screen used to gate [blockExternalResources] on a regex named
 *  `hasRemoteImages` — a stated heuristic standing in for a stated control — and one of them also
 *  skipped it entirely for bodies over 512 KB. Raw sender HTML reached `loadDataWithBaseURL` on
 *  both, and the only thing that stopped it fetching was `blockNetworkLoads` being on: a defence
 *  one mutable WebView setting deep, on a setting the "Show images" button exists to clear.
 *
 *  Stripping first and deriving the flag from the result removes the gate, the size cliff and the
 *  regex together. It costs one extra jsoup parse on bodies that have nothing to strip, which is
 *  the parse the old code already paid on every body that did. */
internal fun renderableBody(
    body: String,
    palette: ThemePalette,
    monoFontFace: String,
    isDark: Boolean,
    keepInlineDataImages: Boolean = false,
): RenderableBody {
    val stripped = blockExternalResources(body, keepInlineDataImages = keepInlineDataImages)
    val keptImages = blockExternalResources(body, keepImages = true, keepInlineDataImages = keepInlineDataImages)
    return RenderableBody(
        stripped = buildEmailBodyHtml(stripped, palette, monoFontFace, isDark),
        // What "Show images" loads: images restored, every OTHER remote resource still stripped.
        // The unmodified body is deliberately never retained — re-loading it is what turned a
        // request for pictures into a request for iframes, fonts and stylesheets as well.
        withImages = buildEmailBodyHtml(keptImages, palette, monoFontFace, isDark),
        hasRemoteImages = stripped != keptImages,
    )
}

/** Wildcard `!important` rules win only because [stripImportant] removes the email's own first. */
internal fun buildEmailBodyHtml(bodyToRender: String, palette: ThemePalette, monoFontFace: String, isDark: Boolean): String {
    val darkModeOverrideCss = if (isDark) {
        """
        html, body {
            background-color: ${palette.bg} !important;
            color: ${palette.inkStrong} !important;
        }
        body * {
            background-color: transparent !important;
            color: ${palette.inkStrong} !important;
        }
        body a, body a * {
            color: ${palette.accent} !important;
        }
        """.trimIndent()
    } else {
        ""
    }
    val body = if (isDark) stripImportant(bodyToRender) else bodyToRender
    return """
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1" />
            <style>
                $monoFontFace
                body {
                    font-family: 'IBM Plex Mono', monospace;
                    font-size: 16px;
                    line-height: 1.5;
                    color: ${palette.inkStrong};
                    background-color: ${palette.bg};
                    margin: 0;
                    padding: 8px;
                    word-break: break-word;
                }
                a { color: ${palette.accent}; }
                img { max-width: 100%; height: auto; }
                pre { white-space: pre-wrap; }
                div.kypost-plain-text {
                    display: block;
                    min-width: 0;
                    max-width: 100%;
                    width: 100%;
                    box-sizing: border-box;
                    margin: 0;
                    white-space: pre-wrap;
                    overflow-wrap: anywhere;
                    word-wrap: break-word;
                    word-break: break-all;
                    overflow-x: hidden;
                    tab-size: 4;
                }
                $darkModeOverrideCss
            </style>
        </head>
        <body>$body</body>
        </html>
    """.trimIndent()
}

/** Whether the preview may stand in for a body the reader does not have.
 *
 *  The inbox is fetched with `bodies=0`, so the body arrives over the network on open and the fetch
 *  can fail — before that it took a missing cache row and effectively never happened. What a failure
 *  leaves behind is the preview, and rendering it is indistinguishable from a short message that
 *  arrived intact. The fallback is for a message the server answered for and had no body for. */
internal fun mayFallBackToPreview(outcome: MailOutcome<MailMessageBody>): Boolean =
    outcome is MailOutcome.Success

/** What to tell the user when the body fetch itself failed, or null when it did not.
 *
 *  Paired with [mayFallBackToPreview]: "No message body available." claims the server answered and
 *  had nothing, which a failed fetch has not established. A failure is the one the user can act on,
 *  so it carries the outcome's own wording — "couldn't reach the mail server" and "this message is
 *  too large for the server to open" call for different responses. */
internal fun bodyFetchFailureNotice(outcome: MailOutcome<MailMessageBody>): String? =
    if (outcome is MailOutcome.Success) null else outcome.userFacingMessage()

/** The notice bar for a message with no text of its own, composed from facts that can co-occur.
 *
 *  A signature notice and a failed fetch are independent, and joining them beats picking one — the
 *  failure is what the user can act on, and a signature notice must not swallow it. [noContent] is
 *  the odd one out: it claims the server answered and had nothing, so it is mutually exclusive with
 *  [fetchFailure], which has established no such thing. */
internal fun emptyBodyNotice(
    signatureNotice: String?,
    fetchFailure: String?,
    noContent: String,
    nothingToRender: Boolean,
): String? = listOfNotNull(
    signatureNotice,
    fetchFailure ?: noContent.takeIf { nothingToRender },
).joinToString("\n\n").ifBlank { null }

/** Pairs the body with its MIME mode before it reaches the WebView. A server-supplied mode wins;
 *  sniffing is only the compatibility fallback for old cache rows. */
internal fun emailBodyToHtml(body: String, mode: String): String {
    when (mode.trim().lowercase()) {
        "html" -> return body
        "plain" -> return "<div class=\"kypost-plain-text\">${escapeEmailText(body)}</div>"
    }
    if (bodyLooksLikeHtml(body)) return body
    return "<div class=\"kypost-plain-text\">${escapeEmailText(body)}</div>"
}

/** Selects native wrapping for explicit plain bodies and old rows whose mode was not persisted. */
internal fun isPlainTextBody(body: String, mode: String): Boolean = when (mode.trim().lowercase()) {
    // Some relay/cache rows incorrectly label Markdown/plain content as HTML. Keep real markup in
    // WebView, but let text-only bodies use the native wrapping view even when that label is wrong.
    "html" -> !bodyLooksLikeHtml(body) || looksLikeMarkdown(body)
    "plain" -> true
    else -> !bodyLooksLikeHtml(body) || looksLikeMarkdown(body)
}

private fun looksLikeMarkdown(body: String): Boolean = body.lineSequence().any { line ->
    line.matches(Regex("^\\s{0,3}#{1,6}\\s+.+")) ||
        line.contains(Regex("\\[[^]]+\\]\\(https?://[^)]+\\)")) ||
        line.trimStart().startsWith("```")
}

private val LONG_PLAIN_TOKEN = Regex("\\S{32,}")

internal fun softWrapPlainText(text: String): String = LONG_PLAIN_TOKEN.replace(text) { match ->
    match.value.chunked(16).joinToString("\u200B")
}

/** Removes loadable resource URLs from the reader pass.
 *
 *  [keepImages] is what "Show images" actually means: `<img>` keeps its `src`, and iframes, media,
 *  stylesheets and CSS `url()` stay stripped whatever the WebView's network flags say. Clearing
 *  `blockNetworkLoads` alone would re-enable all of them, which is not what that button asks for.
 *
 *  Fails CLOSED, matching [org.kysecurity.mail.mail.QuotedHtmlSanitizer]: markup this cannot parse
 *  is markup whose resource URLs it cannot have removed, and handing it back unchanged gave a
 *  sender who can break jsoup every beacon this function exists to strip. */
internal fun blockExternalResources(
    html: String,
    keepImages: Boolean = false,
    // Scoped to decrypted mail only: plaintext HTML never carries attacker-controlled inline
    // images that already passed through PgpMimeReader's byte/part cap.
    keepInlineDataImages: Boolean = false,
    /** Injectable so the fail-closed path can be PROVEN rather than assumed: jsoup is too tolerant
     *  to be made to throw from a test fixture, and "it fails closed" is exactly the kind of claim
     *  that must not rest on reading the code. */
    parse: (String) -> org.jsoup.nodes.Document = org.jsoup.Jsoup::parseBodyFragment,
): String {
    val document = runCatching { parse(html) }.getOrNull()
        ?: return escapeEmailText(html)
    // Dropped whole, not stripped: `srcdoc` carries an ENTIRE inline document that no attribute
    // removal below reaches, and it loads its own stylesheets, fonts and frames the moment "Show
    // images" clears blockNetworkLoads. A frame with no src and no srcdoc renders nothing anyway,
    // so there is nothing to preserve — the composer's Safelist drops the tag for the same reason.
    document.select("iframe").remove()
    // `track` fetches over the network exactly like its sibling `source`, and never as an image.
    val resourceTags = if (keepImages) "video, audio, source, track, embed, object" else "img, video, audio, source, track, embed, object"
    document.select(resourceTags).forEach { element ->
        // A data: raster image is bytes already in hand, not a fetch; every other src goes.
        val keepsSrc = keepInlineDataImages && element.tagName() == "img" &&
            org.kysecurity.mail.pgp.INLINE_DATA_IMAGE_PREFIXES.any { element.attr("src").startsWith(it) }
        if (!keepsSrc) element.removeAttr("src")
        element.removeAttr("srcset")
        element.removeAttr("poster")
        element.removeAttr("data")
    }
    document.select("link").forEach { it.removeAttr("href") }
    // `[style]` is an ATTRIBUTE selector: it matches `<div style=...>` and NOT `<style>`. Both
    // carry `url()`, only the first was ever scrubbed, so a `<style>` block was an unstripped
    // beacon that fired the moment "Show images" cleared blockNetworkLoads.
    document.select("[style]").forEach { element ->
        element.attr("style", stripResourceUrls(element.attr("style")))
    }
    document.select("style").forEach { element ->
        val cleaned = stripResourceUrls(element.data())
        element.empty()
        element.appendChild(org.jsoup.nodes.DataNode(cleaned))
    }
    document.outputSettings().prettyPrint(false)
    return document.body().html()
}

/** Strips every remote-loading CSS construct from one declaration block or `<style>` body.
 *
 *  The escape pass is the same lesson [stripImportantFromCss] already learned, applied to the
 *  other token that matters: `\75 rl(https://x)` is a `url()` to a CSS parser and was not one to
 *  [RESOURCE_URL_PATTERN]. Decoding is conditional so legitimate escapes (`content:"\201C"`)
 *  survive untouched -- the decoded form is only adopted when an escape was HIDING a resource. */
private fun stripResourceUrls(css: String): String {
    val commentless = css.replace(CSS_COMMENT, "")
    val direct = stripResourceFunctions(commentless.replace(CSS_AT_IMPORT, ""))
    val decoded = decodeCssEscapes(commentless)
    if (decoded == commentless) return direct
    val decodedStripped = stripResourceFunctions(decoded.replace(CSS_AT_IMPORT, ""))
    return if (decodedStripped == decoded) direct else decodedStripped
}

/** `@import` takes a bare string as well as a `url()`, so the function scan below cannot see it. */
private val CSS_AT_IMPORT = Regex("""@import\b[^;]*;?""", RegexOption.IGNORE_CASE)

/** Every CSS function that can pull remote bytes.
 *
 *  `image-set()` and `cross-fade()` are listed even though their arguments are usually `url()`
 *  calls the scan would strip anyway, because both also accept a BARE STRING as a URL. */
private val RESOURCE_FUNCTIONS =
    listOf("url", "image-set", "-webkit-image-set", "cross-fade", "-webkit-cross-fade", "src")

/** Replaces every resource-fetching function call with `none`, matching parentheses properly.
 *
 *  This was a regex — `(?:url|image-set|…)\s*\([^)]*\)` — and `[^)]*` is the bug: it stops at the
 *  FIRST `)`, which in CSS is not necessarily the closing one. `url("http://x/a)b")` matched only
 *  as far as `url("http://x/a)`, and what the replacement left behind was `b")` — the tail of a
 *  URL the strip exists to remove. Balanced scanning is not something a regular expression can do,
 *  so this is a scanner. An unbalanced call consumes to the end of the input, which fails closed. */
private fun stripResourceFunctions(css: String): String {
    val out = StringBuilder(css.length)
    var i = 0
    while (i < css.length) {
        val name = RESOURCE_FUNCTIONS.firstOrNull { functionStartsAt(css, i, it) }
        if (name == null) {
            out.append(css[i])
            i++
            continue
        }
        out.append("none")
        val close = matchingParen(css, css.indexOf('(', i + name.length))
        i = if (close < 0) css.length else close + 1
    }
    return out.toString()
}

/** True when [name] begins a function call at [index]: an identifier boundary, the name, optional
 *  whitespace, then `(`. The boundary check stops `background-url(` matching `url`. */
private fun functionStartsAt(css: String, index: Int, name: String): Boolean {
    if (index > 0 && isCssIdentifierChar(css[index - 1])) return false
    if (!css.regionMatches(index, name, 0, name.length, ignoreCase = true)) return false
    var cursor = index + name.length
    while (cursor < css.length && css[cursor].isWhitespace()) cursor++
    return cursor < css.length && css[cursor] == '('
}

private fun isCssIdentifierChar(c: Char): Boolean = c.isLetterOrDigit() || c == '-' || c == '_'

/** The index of the `)` closing the `(` at [open], or -1 if there is none. Quoted sections are
 *  skipped whole: a `)` inside a string is text, and a `\)` inside one is not a delimiter either. */
private fun matchingParen(css: String, open: Int): Int {
    if (open < 0) return -1
    var depth = 0
    var i = open
    var quote: Char? = null
    while (i < css.length) {
        val c = css[i]
        when {
            quote != null && c == '\\' -> i++
            quote != null && c == quote -> quote = null
            quote != null -> Unit
            c == '"' || c == '\'' -> quote = c
            c == '(' -> depth++
            c == ')' -> {
                depth--
                if (depth == 0) return i
            }
        }
        i++
    }
    return -1
}

/** Same conservative fallback as the web reader: use a parser and recognize real HTML tags, so
 *  an address such as `<user@example.com>` remains text while `<center>`/`<o:p>` mail renders. */
private fun bodyLooksLikeHtml(body: String): Boolean {
    if (!body.contains('<')) return false
    val document = runCatching { org.jsoup.Jsoup.parseBodyFragment(body) }.getOrNull() ?: return false
    return document.body().children().any { it.tagName().lowercase() in HTML_TAGS }
}

private val HTML_TAGS = setOf(
    "a", "article", "aside", "b", "blockquote", "body", "br", "button", "center", "code",
    "div", "em", "figure", "font", "footer", "h1", "h2", "h3", "h4", "h5", "h6", "head",
    "header", "hr", "html", "i", "img", "li", "link", "main", "meta", "nav", "ol", "p",
    "pre", "section", "small", "span", "strong", "sub", "sup", "table", "tbody", "td",
    "tfoot", "th", "thead", "title", "tr", "u", "ul", "xml",
)

private fun escapeEmailText(text: String): String = text
    .replace("&", "&amp;")
    .replace("<", "&lt;")
    .replace(">", "&gt;")
    .replace("\"", "&quot;")

/** True only for [ReadOutcome.FetchFailed]; NoEncryptedContent is terminal, so no Retry. */
internal fun showsRetryButton(outcome: ReadOutcome): Boolean = outcome is ReadOutcome.FetchFailed

/** Why a read left the message unread: a string resource and its format argument, or null for an
 *  outcome that is not a failure.
 *
 *  Pure and top-level for the same reason [showsRetryButton] is — every row has to be checkable
 *  without a Context, and the branch that renders it must hold no decisions. Six of these strings
 *  were authored and never referenced: the failure branch passed `""`, so every row below reached
 *  the reader as the same wordless padlock beside an Open-in-webmail button. That is not a
 *  fallback, it is the app declining to say what went wrong, and it hid an on-device decrypt
 *  failure behind what looked like a server refusing the message.
 *
 *  The detail on the last three is deliberate. "bad padding" and "this message is not encrypted to
 *  a key on this device" are different bugs with different fixes, and only the second one means the
 *  enrolment is stale. */
internal fun readFailureNotice(outcome: ReadOutcome): Pair<Int, String?>? = when (outcome) {
    ReadOutcome.NotEnrolled -> R.string.email_pgp_not_enrolled to null
    ReadOutcome.NoSecureLockScreen -> R.string.email_pgp_no_lock_screen to null
    ReadOutcome.TooLarge -> R.string.email_pgp_too_large to null
    ReadOutcome.NotClientProtected -> R.string.email_pgp_not_client_protected to null
    ReadOutcome.NoEncryptedContent -> R.string.email_pgp_no_encrypted_content to null
    // Its own sentence, not NoEncryptedContent's: this message is signed and not encrypted, so
    // "carries no encrypted content" would be true of every signed-only message that reads fine.
    ReadOutcome.NoReadableContent -> R.string.email_pgp_no_readable_content to null
    is ReadOutcome.UnsealFailed -> R.string.email_pgp_unseal_failed to null
    is ReadOutcome.FetchFailed -> R.string.email_pgp_fetch_failed to outcome.message
    // ..._here_failed, not ..._decrypt_failed: the latter is the SERVER's decrypt error, rendered
    // by renderPgpBar. A reader who cannot tell which machine failed cannot act on either.
    is ReadOutcome.DecryptFailed -> R.string.email_pgp_decrypt_here_failed to outcome.message
    // Not failures: the screen goes on offering Decrypt, and a notice there would be an error
    // message for the user's own choice.
    is ReadOutcome.Decrypted, ReadOutcome.NeedsUnlock, ReadOutcome.Cancelled -> null
}

/** A verdict with no resolved mailbox reads as being about the raw sender text, so return NONE. */
internal fun displaySignatureVerdict(outcome: ReadOutcome.Decrypted): PgpSignatureState =
    outcome.signature.takeIf { outcome.resolvedSender.isNotBlank() } ?: PgpSignatureState.NONE

/** A dropped part is said out loud; a complete list needs no sentence. */
internal fun decryptedAttachmentNotice(omitted: Boolean): Int? =
    if (omitted) R.string.email_pgp_attachments_omitted else null

/** False only for CLIENT_PROTECTED: `POST /api/mail/draft` would upload the plaintext. */
internal fun mayReplyOrForward(state: PgpMessageState): Boolean = state != PgpMessageState.CLIENT_PROTECTED

/** Fails closed: an encrypted message assumes CLIENT_PROTECTED until the fetch says otherwise. */
internal fun initialReplyForwardState(pgpEncrypted: Boolean): PgpMessageState =
    if (pgpEncrypted) PgpMessageState.CLIENT_PROTECTED else PgpMessageState.NONE

internal fun safeFileName(raw: String, mimeType: String = ""): String {
    val base = raw.substringAfterLast('/')
        .substringAfterLast('\\')
        .filter { it.isLetterOrDigit() || it in "._- ()[]" }
        .trim()
        .trimStart('.')
        .take(120)
        .ifBlank { "attachment" }
    // The extension comes from the type we declare, never the sender's: `invoice.pdf.apk` got through.
    val expected = extensionForMimeType(mimeType)
    val stem = stripExtensions(base).ifBlank { "attachment" }
    return if (expected == null) stem else "$stem.$expected"
}

/** Repeated, not `substringBeforeLast('.')`: one strip leaves `invoice.pdf.apk` as `invoice.pdf`. */
private val EXTENSION_SUFFIX = Regex("""\.[A-Za-z0-9]{1,5}$""")

internal fun stripExtensions(name: String): String {
    var result = name
    while (true) {
        val stripped = result.replace(EXTENSION_SUFFIX, "")
        if (stripped == result) return result
        result = stripped
    }
}

/** Null means "no extension", which is what an unrecognised type gets. */
internal fun extensionForMimeType(mimeType: String): String? = when (
    mimeType.substringBefore(';').trim().lowercase()
) {
    "application/pdf" -> "pdf"
    "image/jpeg" -> "jpg"
    "image/png" -> "png"
    "image/gif" -> "gif"
    "image/webp" -> "webp"
    "image/heic" -> "heic"
    "text/plain" -> "txt"
    "audio/mpeg" -> "mp3"
    "audio/mp4" -> "m4a"
    "audio/ogg" -> "ogg"
    "video/mp4" -> "mp4"
    "video/webm" -> "webm"
    else -> null
}

/** The sender's Content-Type is unfiltered; anything unlisted becomes application/octet-stream. */
private val VIEWABLE_MIME_TYPES = setOf(
    "application/pdf",
    "image/jpeg", "image/png", "image/gif", "image/webp", "image/heic",
    "text/plain",
    "audio/mpeg", "audio/mp4", "audio/ogg",
    "video/mp4", "video/webm",
)

// Inverse of extensionForMimeType, plus the spellings it does not emit.
private val MIME_TYPE_FOR_EXTENSION: Map<String, String> =
    VIEWABLE_MIME_TYPES.associateBy { extensionForMimeType(it)!! } + ("jpeg" to "image/jpeg")

/** Mailers that label every file application/octet-stream would otherwise cost the user the
 *  extension. Falling back to a benign extension hands a sender nothing: declaring that type
 *  outright already works. */
internal fun safeMimeType(raw: String, name: String = ""): String {
    val declared = raw.substringBefore(';').trim().lowercase()
    if (declared in VIEWABLE_MIME_TYPES) return declared
    return MIME_TYPE_FOR_EXTENSION[name.substringAfterLast('.', "").lowercase()]
        ?: "application/octet-stream"
}

// A CSS comment is transparent between any two tokens, including between `!` and `important`.
private val CSS_COMMENT = Regex("""/\*[^*]*\*+(?:[^/*][^*]*\*+)*/""")

// A CSS escape can spell any letter of "important" (`!\49 mportant` decodes to `!Important`).
private val CSS_ESCAPE = Regex("""\\([0-9a-fA-F]{1,6})\s?""")

private val BANG_CANDIDATE = Regex("""\s*!((?:\\[0-9a-fA-F]{1,6}\s?|[A-Za-z\s]){1,24})""")

/** [CSS_ESCAPE] reaches 0xFFFFFF, past Unicode's 0x10FFFF, and `Character.toChars` throws. */
private fun decodeCssEscapes(candidate: String): String =
    CSS_ESCAPE.replace(candidate) { escape ->
        val codePoint = escape.groupValues[1].toIntOrNull(16)
        if (codePoint != null && Character.isValidCodePoint(codePoint)) {
            String(Character.toChars(codePoint))
        } else {
            escape.value
        }
    }

/** Tolerant of a CSS comment inserted anywhere and of any letter written as an escape. */
internal fun stripImportantFromCss(css: String): String =
    BANG_CANDIDATE.replace(css.replace(CSS_COMMENT, "")) { match ->
        if (decodeCssEscapes(match.groupValues[1]).trim().equals("important", ignoreCase = true)) {
            ""
        } else {
            match.value
        }
    }

/** Parsed with jsoup, so the token patterns only run over one `style` attribute or `<style>`.
 *
 *  Fails OPEN, unlike [blockExternalResources], and that asymmetry is deliberate rather than an
 *  oversight: this is a LEGIBILITY control, not a security one. Its only job is to let the dark
 *  theme's overrides win, so a parse failure costs the reader an email in its own colours and
 *  nothing more. It also runs on [blockExternalResources]'s output, which by then is either a
 *  parsed document re-serialised or plain escaped text -- both of which parse. */
internal fun stripImportant(html: String): String {
    if (html.isBlank()) return html
    val doc = runCatching { org.jsoup.Jsoup.parseBodyFragment(html) }.getOrNull() ?: return html
    doc.outputSettings().prettyPrint(false)

    var changed = false
    doc.select("[style]").forEach { element ->
        val original = element.attr("style")
        val cleaned = stripImportantFromCss(original)
        if (cleaned != original) {
            element.attr("style", cleaned)
            changed = true
        }
    }
    doc.select("style").forEach { element ->
        val original = element.data()
        val cleaned = stripImportantFromCss(original)
        if (cleaned != original) {
            element.empty()
            element.appendChild(org.jsoup.nodes.DataNode(cleaned))
            changed = true
        }
    }
    return if (changed) doc.body().html() else html
}
