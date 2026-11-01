package org.kysecurity.mail

import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Canvas
import android.graphics.Color
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.EditText
import android.widget.PopupMenu
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.view.ActionMode
import androidx.appcompat.widget.SearchView
import androidx.core.content.ContextCompat
import androidx.core.graphics.ColorUtils
import androidx.core.view.isVisible
import androidx.recyclerview.widget.ItemTouchHelper
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.bottomnavigation.BottomNavigationView
import com.google.android.material.navigation.NavigationBarView
import com.google.android.material.snackbar.Snackbar
import com.google.android.material.chip.Chip
import com.google.android.material.chip.ChipGroup
import org.kysecurity.mail.mail.FolderInfo
import org.kysecurity.mail.mail.MAX_ACTION_IDS
import org.kysecurity.mail.mail.MailAccount
import org.kysecurity.mail.mail.MailAction
import org.kysecurity.mail.mail.PendingMail
import org.kysecurity.mail.mail.MailFetchResult
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailRepository
import org.kysecurity.mail.mail.MailRuntime
import org.kysecurity.mail.mail.MailPage
import org.kysecurity.mail.mail.OLDER_MAIL_NOT_SAVED
import org.kysecurity.mail.mail.OLDER_MAIL_UNSUPPORTED
import org.kysecurity.mail.mail.isFlaggedPhishing
import org.kysecurity.mail.mail.notifiedMessage
import org.kysecurity.mail.mail.userFacingMessage
import org.kysecurity.mail.push.PushNotificationDispatcher
import org.kysecurity.mail.ui.observeSplitPane
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.kysecurity.mail.security.LockedActivity

class InboxActivity : LockedActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var keywordChipScroll: View
    private lateinit var keywordChips: ChipGroup
    private lateinit var bottomNav: NavigationBarView
    private lateinit var loadingOverlay: View
    private lateinit var swipeRefresh: androidx.swiperefreshlayout.widget.SwipeRefreshLayout
    private lateinit var loadingStatus: TextView
    private lateinit var cancelLoading: View
    private lateinit var freshnessText: TextView
    private lateinit var emptyText: TextView
    private lateinit var inboxRoot: View
    private lateinit var inboxContent: View
    private lateinit var newMailPill: Chip
    private lateinit var adapter: EmailAdapter
    private val olderFooter = LoadOlderAdapter { loadOlderMail() }
    /** Per folder: where the next older page starts, and folders with nothing older left. */
    private val olderFrontier = mutableMapOf<String, String>()
    private val olderExhausted = mutableSetOf<String>()
    private val ioExecutor: ExecutorService = Executors.newSingleThreadExecutor()
    private val mainHandler = Handler(Looper.getMainLooper())
    private lateinit var mailRepository: MailRepository
    private lateinit var keywordSettings: KeywordSettings
    // Volatile: the IO executor reads it to decide whether its queued refresh is still wanted.
    @Volatile private var currentFolder = "INBOX"

    /** Null in production. Called from inside the deferred swipe action, on the worker thread and
     *  at the moment it actually runs, so a test can see the folder that action really used. */
    @androidx.annotation.VisibleForTesting
    internal var rowActionObserverForTest: ((String, String) -> Unit)? = null

    /** Null in production. Called on the main thread once a failed row action has been shown. */
    @androidx.annotation.VisibleForTesting
    internal var rowActionFailureShownForTest: (() -> Unit)? = null

    /** Null in production. Called on the main thread when an earlier account's outcome is dropped. */
    @androidx.annotation.VisibleForTesting
    internal var rowActionDroppedForTest: (() -> Unit)? = null

    /** Null in production. Runs on the IO thread after the cache paint, before the network fetch. */
    @androidx.annotation.VisibleForTesting
    internal var beforeNetworkRefreshForTest: ((folder: String) -> Unit)? = null

    /** Null in production. Stands in for the active pairing's account in a row action's check. */
    @androidx.annotation.VisibleForTesting
    internal var activeAccountForTest: (() -> MailAccount?)? = null

    /** The account the rows on screen were read under; row actions carry it to the request. */
    @Volatile private var shownAccount: MailAccount? = null
    private var lastAppliedTheme: ThemeChoice? = null
    private var pendingScrollPosition: Int = 0

    private var selectedTab = KeywordTabs.ALL
    private var allEmails: List<Email> = emptyList()
    private var pendingMessageId: String? = null
    private var pendingSender: String? = null
    private var pendingSubject: String? = null
    private var pendingMessageDeadlineMs: Long = 0L
    private val refreshedAtByFolder = mutableMapOf<String, Long>()
    /** Last folder the relay confirmed; before that an empty list is unknown, not empty. */
    private var loadedFolder: String? = null
    private var searchItem: MenuItem? = null
    /** Non-null while searching; results are shown instead of the folder once they arrive. */
    private var searchQuery: String? = null
    private var searchResults: List<Email>? = null
    private val selectedIds = linkedSetOf<String>()
    private var selectionMode: ActionMode? = null
    private val heldActions = PendingRowActions()
    private var undoBar: Snackbar? = null
    private var newMailCount = 0

    /** The folder the list last painted from a refresh; only a repaint of it can bring new mail. */
    private var paintedFolder: String? = null
    /** Unread rows per folder in the cache, as of the last refresh; labels the folder picker. */
    private var unreadByFolder: Map<String, Int> = emptyMap()

    private val refreshRunnable = object : Runnable {
        override fun run() {
            refreshInbox()
            scheduleNextRefresh()
        }
    }

    // The backend can take seconds to index a just-pushed email, so poll instead of a single try.
    private val pendingMessagePollRunnable = Runnable { refreshInbox() }

    private val emailDetailLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == RESULT_OK) {
            val removedId = result.data?.getStringExtra(EmailDetailActivity.EXTRA_REMOVED_EMAIL_ID)
            if (removedId != null) {
                allEmails = allEmails.filter { it.id != removedId }
                searchResults = searchResults?.filter { it.id != removedId }
                rebuildTabs(allEmails)
                renderFilteredEmails()
            }
            // Already confirmed by the relay and written to Room; this only repaints the row.
            val unreadId = result.data?.getStringExtra(EmailDetailActivity.EXTRA_MARKED_UNREAD_ID)
            val unreadFolder = result.data?.getStringExtra(EmailDetailActivity.EXTRA_MARKED_UNREAD_FOLDER)
            if (unreadId != null && unreadFolder != null) showStatus(unreadId, unreadFolder, "unread")
        }
    }

    private val foldersLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        val folder = result.data?.getStringExtra(FoldersActivity.EXTRA_FOLDER)
        if (result.resultCode == RESULT_OK && folder != null) switchFolder(folder)
    }

    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        savedInstanceState?.let { state ->
            currentFolder = state.getString(STATE_FOLDER, currentFolder)
            selectedTab = state.getString(STATE_TAB, selectedTab)
            pendingScrollPosition = state.getInt(STATE_SCROLL, 0)
        }
        setContentView(R.layout.activity_inbox)
        applyThemeToActivity(this)
        lastAppliedTheme = getStoredThemeChoice(this)

        mailRepository = MailRuntime.graph(this).repository
        keywordSettings = KeywordSettings(this)

        initViews()
        applyFolderTitle()
        applyTopInsetWithHeader(this, inboxContent)
        applyPrimaryNavigationInsets(this, bottomNav)
        applyInboxThemeChrome()
        setupRecyclerView()
        setupTabs()
        setupBottomNav()
        setupSwipeGestures()
        // Beside an open message a right-hand rail moves to that pane's end edge
        // (EmailDetailActivity); a left-hand one stays here, on the window's start edge.
        val railHere = !railAtEnd(this)
        observeSplitPane(this) { split -> bottomNav.isVisible = !split || railHere }

        // A recreate already consumed the tap; re-reading it reopens the message and resets the folder.
        if (savedInstanceState == null && takeNotificationTarget(intent)) {
            currentFolder = "INBOX"
        }
    }

    /** Moves a notification's target into the pending fields and off [intent], so it acts once. */
    private fun takeNotificationTarget(intent: Intent): Boolean {
        pendingMessageId = intent.getStringExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID) ?: return false
        pendingSender = intent.getStringExtra(PushNotificationDispatcher.EXTRA_SENDER)
        pendingSubject = intent.getStringExtra(PushNotificationDispatcher.EXTRA_SUBJECT)
        pendingMessageDeadlineMs = System.currentTimeMillis() + PENDING_MESSAGE_TIMEOUT_MS
        intent.removeExtra(PushNotificationDispatcher.EXTRA_MESSAGE_ID)
        intent.removeExtra(PushNotificationDispatcher.EXTRA_SENDER)
        intent.removeExtra(PushNotificationDispatcher.EXTRA_SUBJECT)
        return true
    }

    private fun applyFolderTitle() {
        val folderLabel = currentFolderLabel()
        val title = getString(R.string.inbox_heading, folderLabel)
        setTitle(title)
        applyKyPostTopBar(this, folderLabel)
        if (::bottomNav.isInitialized) {
            bottomNav.menu.findItem(R.id.nav_inbox)?.title = folderLabel
        }
    }

    private fun currentFolderLabel(): String {
        return when {
            currentFolder == "Junk" -> getString(R.string.nav_junk)
            currentFolder == "Trash" -> getString(R.string.nav_trash)
            currentFolder == ARCHIVE_PARENT_FOLDER -> getString(R.string.nav_archive)
            currentFolder.startsWith("$ARCHIVE_PARENT_FOLDER/") -> currentFolder.substringAfterLast('/')
            currentFolder.equals("INBOX", ignoreCase = true) -> getString(R.string.nav_inbox)
            else -> specialFolderOf(currentFolder)?.let { getString(it.label) } ?: mailboxLeaf(currentFolder)
        }
    }

    override fun onStartUnlocked() {
        // A failed read clears its overlay; repaint from the cache so the row shows unread again.
        mailRepository.setOverlayListener { runOnUiThread { repaintFromCache() } }
        refreshInbox()
        scheduleNextRefresh()
    }

    private fun repaintFromCache() {
        if (isFinishing || isDestroyed) return
        val folder = currentFolder
        executeGuarded(folder) {
            val cached = mailRepository.cachedEmails(folder)
            runOnUiThread { applyRefreshedEmails(folder, cached, isFinal = false, errorMessage = null) }
        }
    }

    /** An uncaught throw on [ioExecutor] kills the process. A failure keeps the rows on screen,
     *  marks [folder] stale and says so. Logs the type only: a message can carry mail content. */
    private fun executeGuarded(folder: String, work: () -> Unit) = ioExecutor.execute {
        try {
            work()
        } catch (e: InterruptedException) {
            // shutdownNow() in onDestroy (a fold, rotation or close mid-refresh): nothing to repaint.
            Thread.currentThread().interrupt()
        } catch (e: RuntimeException) {
            android.util.Log.w("InboxActivity", "Inbox refresh failed: ${e.javaClass.name}")
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                applyRefreshedEmails(folder, allEmails, isFinal = true, errorMessage = getString(R.string.inbox_refresh_failed))
            }
        }
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return

        if (getStoredThemeChoice(this) != lastAppliedTheme) {
            recreate()
            return
        }

        applyThemeToActivity(this)
        applyInboxThemeChrome()
        rebuildTabs(allEmails)
        renderFilteredEmails()
    }

    override fun onStop() {
        super.onStop()
        if (redirectedToUnlock) return
        mailRepository.setOverlayListener(null)
        heldActions.flush()
        // Nothing is left for its Undo to take back.
        undoBar?.dismiss()
        mainHandler.removeCallbacks(refreshRunnable)
        mainHandler.removeCallbacks(pendingMessagePollRunnable)
    }

    override fun onDestroy() {
        super.onDestroy()
        // No redirectedToUnlock guard: ioExecutor is a property initializer, so it exists even
        // when onCreate bailed, and skipping shutdown would leak its thread.
        ioExecutor.shutdownNow()
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // Identifiers and positions only. No subjects, senders or bodies: this Bundle is
        // system-managed storage outside the app's control.
        outState.putString(STATE_FOLDER, currentFolder)
        outState.putString(STATE_TAB, selectedTab)
        // A still-unconsumed pending target wins: the list is empty until the folder has loaded.
        val layoutManager = recyclerView.layoutManager as? LinearLayoutManager
        val visible = layoutManager?.findFirstVisibleItemPosition() ?: 0
        outState.putInt(STATE_SCROLL, if (pendingScrollPosition > 0) pendingScrollPosition else visible)
    }

    private fun initViews() {
        inboxRoot = findViewById(R.id.inboxRoot)
        inboxContent = findViewById(R.id.inboxContent)
        recyclerView = findViewById(R.id.recyclerViewInbox)
        keywordChipScroll = findViewById(R.id.keywordChipScroll)
        keywordChips = findViewById(R.id.keywordChipGroup)
        bottomNav = findViewById(R.id.bottomNavigation)
        loadingOverlay = findViewById(R.id.loadingOverlay)
        swipeRefresh = findViewById(R.id.inboxSwipeRefresh)
        // forceFullResync: a delta cannot repair a drifted cache, so a pull re-reads the folder.
        swipeRefresh.setOnRefreshListener {
            // Unknown until the relay answers again, so not "No messages" while it is asked.
            loadedFolder = null
            renderFilteredEmails()
            refreshInbox(forceFullResync = true)
        }
        loadingStatus = findViewById<TextView>(R.id.loadingStatus)
        cancelLoading = findViewById(R.id.cancelLoading)
        freshnessText = findViewById(R.id.inboxFreshness)
        emptyText = findViewById(R.id.inboxEmpty)
        newMailPill = findViewById(R.id.newMailPill)
        newMailPill.setOnClickListener {
            recyclerView.smoothScrollToPosition(0)
            hideNewMailPill()
        }

        cancelLoading.setOnClickListener {
            pendingMessageId = null
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            loadingOverlay.visibility = View.GONE
        }
    }

    private fun applyInboxThemeChrome() {
        val palette = getStoredThemePalette(this)
        val bg = Color.parseColor(palette.bg)

        inboxRoot.setBackgroundColor(bg)
        inboxContent.setBackgroundColor(bg)
        recyclerView.setBackgroundColor(bg)
        // The keyword chips sit on the page, not in a card; the tree walk painted both panel.
        keywordChipScroll.setBackgroundColor(bg)
        keywordChips.setBackgroundColor(bg)

        applyFolderTitle()

        applyEmptyStateBackground(this, emptyText)
        applyPillChipTheme(this, newMailPill)

        // Re-style every existing chip in place so a theme switch recolors them even when
        // rebuildTabs() short-circuits because the keyword set itself hasn't changed.
        for (index in 0 until keywordChips.childCount) {
            (keywordChips.getChildAt(index) as? Chip)?.let { styleKeywordChip(it) }
        }

        applyPrimaryNavigationTheme(this, bottomNav)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        if (redirectedToUnlock) return
        setIntent(intent)
        if (takeNotificationTarget(intent)) {
            currentFolder = "INBOX"
            exitSearch()
            applyFolderTitle()
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            refreshInbox()
        }
    }

    private fun setupRecyclerView() {
        adapter = EmailAdapter(
            emptyList(),
            onEmailLongClick = ::toggleSelected,
            onEmailClick = { email -> if (selectionMode != null) toggleSelected(email) else openEmailDetail(email) },
            // Like the swipes, off while selecting.
            rowActions = listOf(
                R.string.action_archive to { email: Email ->
                    if (selectionMode == null) {
                        submitRowAction(email, getString(R.string.action_archive), mailRepository::archive)
                    }
                },
                R.string.action_delete to { email: Email ->
                    if (selectionMode == null) {
                        submitRowAction(email, getString(R.string.action_delete), mailRepository::delete)
                    }
                },
            ),
        )
        recyclerView.layoutManager = LinearLayoutManager(this)
        recyclerView.adapter = androidx.recyclerview.widget.ConcatAdapter(adapter, olderFooter)
        recyclerView.addOnScrollListener(object : RecyclerView.OnScrollListener() {
            override fun onScrolled(recyclerView: RecyclerView, dx: Int, dy: Int) {
                if (!recyclerView.canScrollVertically(-1)) hideNewMailPill()
            }
        })
    }

    /** Pages from the last page's `nextBefore`; the first page starts at the oldest row held. */
    private fun loadOlderMail() {
        if (olderFooter.loading) return
        val folder = currentFolder
        val frontier = olderFrontier[folder]
        olderFooter.loading = true
        ioExecutor.execute {
            var outcome: MailOutcome<MailPage>? = null
            var emails: List<Email>? = null
            var unread: Map<String, Int>? = null
            var failed = false
            try {
                // The anchor is read from Room, not allEmails: right after a folder switch that is
                // still the old folder.
                outcome = mailRepository.loadOlderFrom(folder, frontier)
                mailRepository.cachedEmailsAndUnread(folder).let { (rows, counts) ->
                    emails = rows
                    unread = counts
                }
            } catch (e: RuntimeException) {
                // An exception here would kill the worker thread and the app with it.
                android.util.Log.w("InboxActivity", "Loading older mail failed", e)
                failed = true
            } finally {
                // Null means "nothing to page from" only when nothing failed.
                if (failed && outcome == null) outcome = MailOutcome.BadRequest(OLDER_MAIL_NOT_SAVED)
                val result = outcome
                val painted = emails
                val counts = unread
                runOnUiThread {
                    counts?.let { unreadByFolder = it }
                    onOlderMailLoaded(folder, result, painted)
                }
            }
        }
    }

    private fun onOlderMailLoaded(folder: String, outcome: MailOutcome<MailPage>?, emails: List<Email>?) {
        olderFooter.loading = false
        val message = (outcome as? MailOutcome.BadRequest)?.message
        when {
            outcome is MailOutcome.Success -> {
                val next = outcome.value.nextBefore
                if (outcome.value.hasMore == true && next != null) olderFrontier[folder] = next else olderExhausted += folder
            }
            outcome == null || message == OLDER_MAIL_UNSUPPORTED -> olderExhausted += folder
            // A stale frontier answers 400 forever; retry from the oldest row instead. Any other
            // failure (network, storage) keeps the frontier, so the retry asks for the same page.
            outcome is MailOutcome.BadRequest && message != OLDER_MAIL_NOT_SAVED -> olderFrontier.remove(folder)
        }
        if (folder != currentFolder) return
        if (emails != null) {
            allEmails = emails
            rebuildTabs(emails)
            renderFilteredEmails()
        }
        outcome?.userFacingMessage()?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
    }

    /** Server first: the row changes only once the relay confirms, so a server without the
     *  unread action leaves it as it was and the failure is toasted. */
    private fun setReadState(email: Email, read: Boolean) {
        val folder = email.sourceFolder()
        val label = getString(if (read) R.string.action_mark_read else R.string.action_mark_unread)
        val repository = mailRepository
        val session = ProcessState.generation()
        // Ordered with any read a detail screen left in flight, so this cannot be undone by it.
        val setState = ReadStateLane.ordered {
            if (read) repository.markRead(email.id, folder, session) else repository.markUnread(email.id, folder, session)
        }
        MailBackgroundExecutor.submitReporting(this, label) {
            val outcome = setState()
            if (outcome is MailOutcome.Success) {
                runOnUiThread { showStatus(email.id, folder, if (read) "read" else "unread") }
            }
            outcome
        }
    }

    /** Matches folder as well as id: after a folder switch the list can still hold another
     *  mailbox's rows, and a UID repeats across mailboxes. */
    private fun showStatus(id: String, folder: String, status: String) {
        if (redirectedToUnlock || isDestroyed) return
        // Whatever folder is on screen: the picker counts every folder.
        recountUnread()
        allEmails = allEmails.map { if (it.id == id && it.sourceFolder() == folder) it.copy(status = status) else it }
        searchResults = searchResults?.map { if (it.id == id && it.sourceFolder() == folder) it.copy(status = status) else it }
        rebuildTabs(allEmails)
        renderFilteredEmails()
    }

    /** The row's own mailbox, not the screen's. An IMAP UID is unique only within one folder, so
     *  a deferred action that re-reads [currentFolder] can hit the same id in a different one. */
    private fun Email.sourceFolder(): String = folder.ifBlank { currentFolder }

    private fun openEmailDetail(email: Email) {
        val intent = Intent(this, EmailDetailActivity::class.java)
        intent.putExtra("email_id", email.id)
        intent.putExtra("email_subject", email.subject)
        intent.putExtra("email_sender", email.sender)
        intent.putExtra("email_body_mode", email.bodyMode)
        intent.putExtra("email_folder", email.sourceFolder())
        // A search result has no Room row, so these are the only copy of its recipients.
        intent.putExtra("email_sent_to", email.sentTo)
        intent.putExtra("email_cc", email.cc)
        intent.putExtra("email_has_attachments", email.hasAttachments)
        intent.putExtra("email_pgp_encrypted", email.pgpEncrypted)
        intent.putExtra("email_pgp_decrypt_error", email.pgpDecryptError)
        // Signature state is what separates an authentic signed message from an impersonation.
        intent.putExtra("email_pgp_signed", email.pgpSigned)
        intent.putExtra("email_pgp_verified", email.pgpVerified)
        intent.putExtra("email_pgp_signer_fingerprint", email.pgpSignerFingerprint)
        // The server's $Phishing IMAP keyword; see mail/PhishingFlag.kt for the case-insensitive match.
        intent.putExtra("email_suspicious", isFlaggedPhishing(email.keywords))
        intent.putExtra(EmailDetailActivity.EXTRA_FOLDER_LABEL, currentFolderLabel())
        emailDetailLauncher.launch(intent)
    }

    private fun checkPendingMessage(emails: List<Email>, isFinal: Boolean = false) {
        val id = pendingMessageId ?: return
        val email = notifiedMessage(emails, id, pendingSender, pendingSubject)

        if (email != null) {
            pendingMessageId = null
            pendingSender = null
            pendingSubject = null
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            openEmailDetail(email)
            return
        }

        if (!isFinal) return

        if (System.currentTimeMillis() < pendingMessageDeadlineMs) {
            // Still inside the deep-link wait window: the backend may not have indexed it yet.
            mainHandler.removeCallbacks(pendingMessagePollRunnable)
            mainHandler.postDelayed(pendingMessagePollRunnable, PENDING_MESSAGE_POLL_INTERVAL_MS)
        } else {
            pendingMessageId = null
            pendingSender = null
            pendingSubject = null
            Toast.makeText(this, R.string.email_not_found, Toast.LENGTH_SHORT).show()
        }
    }

    private fun setupTabs() {
        keywordChips.setOnCheckedStateChangeListener { group, checkedIds ->
            val checkedId = checkedIds.firstOrNull() ?: return@setOnCheckedStateChangeListener
            // The tag, not the text: the text carries the unread count.
            val tab = (group.findViewById<Chip>(checkedId))?.tag as? String ?: KeywordTabs.ALL
            // A chip rebuild re-checks the same tab; only a real switch makes the count stale.
            if (tab != selectedTab) hideNewMailPill()
            selectedTab = tab
            renderFilteredEmails()
        }

        rebuildTabs(emptyList())
    }

    private fun styleKeywordChip(chip: Chip) = applyPillChipTheme(this, chip)

    private fun scheduleNextRefresh() {
        mainHandler.removeCallbacks(refreshRunnable)
        // ponytail: foreground best-effort cadence; upgrade path is server push + work resumption.
        mainHandler.postDelayed(refreshRunnable, REFRESH_INTERVAL_MS)
    }

    /** [forceFullResync] sends `since=0`: a delta cannot repair a cache that has drifted. */
    private fun refreshInbox(forceFullResync: Boolean = pendingMessageId != null) {
        // Render the Room cache first on a cold open; never on a pull, which has its own spinner.
        val showCacheFirst = (allEmails.isEmpty() || pendingMessageId != null) && !forceFullResync
        if (showCacheFirst) {
            loadingOverlay.visibility = android.view.View.VISIBLE
            val status = if (pendingMessageId != null) {
                val detail = if (!pendingSender.isNullOrBlank()) " from $pendingSender" else ""
                getString(R.string.finding_email) + detail
            } else {
                getString(R.string.loading_emails)
            }
            loadingStatus.text = status
            cancelLoading.visibility = if (pendingMessageId != null) View.VISIBLE else View.GONE
        }
        // Snapshotted here: this request belongs to the folder on screen now, and the executor
        // may not reach it until the user has moved on. See [applyRefreshedEmails].
        val requestedFolder = currentFolder
        executeGuarded(requestedFolder) {
            try {
                refreshInboxOnIo(requestedFolder, showCacheFirst, forceFullResync)
            } finally {
                runOnUiThread { swipeRefresh.isRefreshing = false }
            }
        }
    }

    private fun refreshInboxOnIo(folder: String, showCacheFirst: Boolean, forceFullResync: Boolean) {
        // Already obsolete before it started: fetching a folder nobody is looking at buys nothing.
        if (folder != currentFolder) return
        // Read before the rows: the account they are shown, and acted on, under.
        val account = mailRepository.currentAccount()
        // Not only on a cold open: returning from a message must show its read overlay now, not
        // after the network answers. A pull re-reads the folder and paints once.
        if (showCacheFirst || !forceFullResync) {
            val (cached, unread) = mailRepository.cachedEmailsAndUnread(folder)
            runOnUiThread { unreadByFolder = unread }
            if (cached.isNotEmpty()) {
                runOnUiThread {
                    applyRefreshedEmails(folder, cached, isFinal = false, errorMessage = null, account = account)
                }
            }
        }
        beforeNetworkRefreshForTest?.invoke(folder)
        val outcome: MailOutcome<MailFetchResult> =
            mailRepository.refreshFolder(folder, forceFullResync = forceFullResync)
        val (emails, unread) = mailRepository.cachedEmailsAndUnread(folder)
        runOnUiThread { unreadByFolder = unread }
        val errorMessage = outcome.userFacingMessage()
        keywordSettings.rememberKeywords(emails.flatMap { it.keywords }.toSet())
        runOnUiThread {
            applyRefreshedEmails(
                folder,
                emails,
                isFinal = true,
                errorMessage = errorMessage,
                refreshedAt = System.currentTimeMillis().takeIf { outcome is MailOutcome.Success },
                account = account,
            )
        }
    }

    /** Paints only if [folder] is still the folder on screen. The IO executor is FIFO, but a
     *  refresh queued before a folder switch still *completes* after it, and rendering its rows
     *  would put one mailbox's mail under another's title — and under its swipe actions. */
    @androidx.annotation.VisibleForTesting
    internal fun applyRefreshedEmails(
        folder: String,
        emails: List<Email>,
        isFinal: Boolean,
        errorMessage: String?,
        refreshedAt: Long? = null,
        account: MailAccount? = shownAccount,
    ) {
        if (folder != currentFolder) return
        shownAccount = account
        // A failed fetch un-confirms the folder: its emptiness is no longer known.
        if (isFinal) loadedFolder = folder.takeIf { refreshedAt != null }
        // Snapshotted before rebuildTabs: a chip rebuild re-renders through the tab listener.
        val previous = adapter.currentEmails().takeIf { paintedFolder == folder }
        val tabBefore = selectedTab
        paintedFolder = folder
        allEmails = emails
        rebuildTabs(emails)
        renderFilteredEmails(previous?.takeIf { selectedTab == tabBefore })
        checkPendingMessage(emails, isFinal = isFinal)
        refreshedAt?.let { refreshedAtByFolder[folder] = it }
        renderFreshness()
        // A cache-first pass leaves the overlay up while a deep link is still hunting its message.
        if (isFinal || pendingMessageId == null) {
            loadingOverlay.visibility = View.GONE
        }
        if (errorMessage != null) {
            Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
        }
    }

    private fun renderFreshness() {
        val refreshedAt = refreshedAtByFolder[currentFolder]
        if (refreshedAt == null) {
            freshnessText.setText(R.string.inbox_not_updated)
            return
        }
        val relative = android.text.format.DateUtils.getRelativeTimeSpanString(
            refreshedAt,
            System.currentTimeMillis(),
            android.text.format.DateUtils.MINUTE_IN_MILLIS,
        )
        freshnessText.text = getString(R.string.inbox_updated, relative)
    }

    private fun rebuildTabs(emails: List<Email>) {
        // Show every remembered keyword, not just this batch's: a tab must not vanish when mail moves.
        val discoveredThisBatch = KeywordTabs.buildTabs(emails).drop(1).toSet()
        keywordSettings.rememberKeywords(discoveredThisBatch)
        val allowedKeywords = keywordSettings.getOrderedKeywords().filter(keywordSettings::isKeywordVisible)
        val tabs = KeywordTabs.visibleTabs(keywordSettings.isAllTabVisible(), allowedKeywords)

        val current = mutableListOf<String>()
        for (index in 0 until keywordChips.childCount) {
            current.add((keywordChips.getChildAt(index) as? Chip)?.tag as? String ?: "")
        }
        val checked = keywordChips.findViewById<Chip?>(keywordChips.checkedChipId)?.tag as? String
        // With All hidden there may be no tab at all; then All is still the right filter, unchipped.
        if (!tabs.contains(selectedTab)) {
            selectedTab = tabs.firstOrNull() ?: KeywordTabs.ALL
        }
        if (tabs != current || (tabs.isNotEmpty() && checked != selectedTab)) {
            keywordChips.removeAllViews()
            tabs.forEach { keyword ->
                val chip = Chip(this).apply {
                    tag = keyword
                    text = keyword
                    isCheckable = true
                    isClickable = true
                    isChecked = keyword == selectedTab
                }
                styleKeywordChip(chip)
                keywordChips.addView(chip)
            }
        }

        // Unread counts change on a refresh even when the keyword set does not, so refresh always.
        val dotSizePx = (7 * resources.displayMetrics.density).toInt()
        // Rows held for Undo are hidden, so they are not counted either.
        val held = heldActions.heldEmails().map { it.rowKey() }.toSet()
        val unreadByTab = KeywordTabs.unreadCounts(emails.filter { it.rowKey() !in held })
        for (index in 0 until keywordChips.childCount) {
            val chip = keywordChips.getChildAt(index) as? Chip ?: continue
            val keyword = chip.tag as? String ?: continue
            val unread = unreadByTab[keyword] ?: 0
            val hasUnread = unread > 0
            chip.text = withUnread(keyword, unread)
            chip.contentDescription = if (hasUnread) {
                resources.getQuantityString(R.plurals.tab_unread_description, unread, keyword, unread)
            } else {
                null
            }
            chip.setBold(hasUnread)
            chip.isChipIconVisible = hasUnread
            if (hasUnread) {
                chip.chipIconSize = dotSizePx.toFloat()
                chip.chipIcon = unreadDotDrawable(this, sizeDp = 7)
                // The unread dot stays accent: a selected chip is accentSoft now, not an accent fill.
                chip.chipIconTint = ColorStateList.valueOf(Color.parseColor(getStoredThemePalette(this).accent))
            } else {
                chip.chipIcon = null
            }
        }
    }

    /** Rows added above [previous]'s top row are scrolled to, or announced by the pill when the
     *  user has scrolled away. A pending saved-position restore wins over both. Search results
     *  are not the folder, so they never count as new mail. Rows held for Undo are hidden. */
    private fun renderFilteredEmails(previous: List<Email>? = null) {
        val held = heldActions.heldEmails().map { it.rowKey() }.toSet()
        val results = searchResults?.filter { it.rowKey() !in held }
        val filtered = results ?: KeywordTabs.filterEmails(allEmails, selectedTab).filter { it.rowKey() !in held }
        val added = if (results == null) previous?.let { newRowsAbove(it, filtered) } ?: 0 else 0
        val wasAtTop = !recyclerView.canScrollVertically(-1)
        adapter.updateEmails(filtered)
        olderFooter.shown = results == null && allEmails.isNotEmpty() && currentFolder !in olderExhausted
        keywordChipScroll.visibility = if (searchQuery == null) View.VISIBLE else View.GONE
        emptyText.text = if (results != null) {
            getString(R.string.search_no_results)
        } else {
            getString(R.string.inbox_empty, currentFolderLabel())
        }
        val empty = if (results != null) results.isEmpty() else inboxEmptyVisible(filtered.size, loadedFolder, currentFolder)
        emptyText.visibility = if (empty) View.VISIBLE else View.GONE
        if (pendingScrollPosition > 0 && adapter.itemCount > 0) {
            val target = pendingScrollPosition.coerceAtMost(adapter.itemCount - 1)
            pendingScrollPosition = 0
            recyclerView.scrollToPosition(target)
            return
        }
        if (added == 0) return
        if (wasAtTop) {
            recyclerView.scrollToPosition(0)
        } else {
            newMailCount += added
            newMailPill.text = resources.getQuantityString(R.plurals.inbox_new_mail, newMailCount, newMailCount)
            newMailPill.visibility = View.VISIBLE
        }
    }

    private fun hideNewMailPill() {
        newMailCount = 0
        newMailPill.visibility = View.GONE
    }

    /** Counts come from the local cache, so they cover the mail this device holds. The label is
     *  bidi-isolated so a right-to-left name cannot swallow the number. */
    private fun withUnread(label: String, unread: Int): String =
        if (unread > 0) {
            getString(R.string.label_with_unread, androidx.core.text.BidiFormatter.getInstance().unicodeWrap(label), unread)
        } else {
            label
        }

    /** Re-reads the picker's counts from Room after a confirmed change, never adjusting them by
     *  arithmetic, which a snapshot taken after the change would count twice. On [ioExecutor],
     *  which runs every refresh too, so an older snapshot cannot land after this one. */
    private fun recountUnread() {
        if (isDestroyed || ioExecutor.isShutdown) return
        executeGuarded(currentFolder) {
            val unread = mailRepository.unreadCounts()
            runOnUiThread { unreadByFolder = unread }
        }
    }

    private fun switchFolder(folder: String) {
        hideNewMailPill()
        currentFolder = folder
        selectedTab = KeywordTabs.ALL
        selectionMode?.finish()
        exitSearch()
        emptyText.visibility = View.GONE
        // Empty, so refreshInbox takes its cold-open path: loading state, then this folder's cache.
        allEmails = emptyList()
        renderFilteredEmails()
        applyFolderTitle()
        renderFreshness()
        refreshInbox()
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        if (redirectedToUnlock) return false
        val ink = readableOn(Color.parseColor(getStoredThemePalette(this).bg))
        val searchView = SearchView(this).apply {
            imeOptions = imeOptions or android.view.inputmethod.EditorInfo.IME_FLAG_NO_PERSONALIZED_LEARNING
            queryHint = getString(R.string.search_hint)
            // The query is mail content; keep it out of the system-managed state Bundle.
            isSaveFromParentEnabled = false
            findViewById<EditText>(androidx.appcompat.R.id.search_src_text)?.apply {
                setTextColor(ink)
                setHintTextColor(ColorUtils.setAlphaComponent(ink, 0x99))
            }
            findViewById<android.widget.ImageView>(androidx.appcompat.R.id.search_close_btn)?.setColorFilter(ink)
            setOnQueryTextListener(object : SearchView.OnQueryTextListener {
                override fun onQueryTextSubmit(query: String): Boolean {
                    if (query.isNotBlank()) runSearch(query.trim())
                    clearFocus()
                    return true
                }

                // Searching is submit-only, but results must match the text on screen.
                override fun onQueryTextChange(newText: String): Boolean {
                    if (searchQuery != null && newText.trim() != searchQuery) endSearch()
                    return false
                }
            })
        }
        searchItem = menu.add(0, MENU_SEARCH, 0, R.string.search_hint).apply {
            icon = ContextCompat.getDrawable(this@InboxActivity, R.drawable.ic_search)?.mutate()?.apply { setTint(ink) }
            actionView = searchView
            setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS or MenuItem.SHOW_AS_ACTION_COLLAPSE_ACTION_VIEW)
            setOnActionExpandListener(object : MenuItem.OnActionExpandListener {
                override fun onMenuItemActionExpand(item: MenuItem): Boolean = true

                override fun onMenuItemActionCollapse(item: MenuItem): Boolean {
                    endSearch()
                    return true
                }
            })
        }
        return super.onCreateOptionsMenu(menu)
    }

    /** Results land only if this query is still the one on screen, in the folder it searched. */
    private fun runSearch(query: String) {
        selectionMode?.finish()
        searchQuery = query
        renderFilteredEmails()
        val folder = currentFolder
        ioExecutor.execute {
            val outcome = mailRepository.search(query, folder)
            runOnUiThread { applySearchResults(query, folder, outcome) }
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun applySearchResults(query: String, folder: String, outcome: MailOutcome<List<Email>>) {
        if (searchQuery != query || folder != currentFolder) return
        // Rows selected while this loaded may not be among the results; never act on unseen rows.
        selectionMode?.finish()
        // A failure must not leave an earlier query's results under this one.
        searchResults = (outcome as? MailOutcome.Success)?.value
        renderFilteredEmails()
        outcome.userFacingMessage()?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
    }

    private fun endSearch() {
        selectionMode?.finish()
        searchQuery = null
        searchResults = null
        renderFilteredEmails()
    }

    private fun exitSearch() {
        if (searchItem?.isActionViewExpanded == true) searchItem?.collapseActionView() else endSearch()
    }

    /** The one way into the selection, so the relay's batch limit is enforced here and only here. */
    private fun toggleSelected(email: Email) {
        if (!selectedIds.remove(email.id)) {
            if (selectedIds.size >= MAX_ACTION_IDS) {
                Toast.makeText(this, getString(R.string.selection_limit, MAX_ACTION_IDS), Toast.LENGTH_SHORT).show()
                return
            }
            selectedIds.add(email.id)
        }
        if (selectedIds.isEmpty()) {
            selectionMode?.finish()
            return
        }
        if (selectionMode == null) selectionMode = startSupportActionMode(selectionCallback)
        selectionMode?.title = resources.getQuantityString(R.plurals.selection_count, selectedIds.size, selectedIds.size)
        adapter.setSelection(selectedIds)
    }

    private val selectionCallback = object : ActionMode.Callback {
        override fun onCreateActionMode(mode: ActionMode, menu: Menu): Boolean {
            val ink = com.google.android.material.color.MaterialColors.getColor(
                this@InboxActivity, android.R.attr.textColorPrimary, Color.WHITE,
            )
            fun add(id: Int, label: Int, icon: Int) = menu.add(0, id, id, label).apply {
                this.icon = ContextCompat.getDrawable(this@InboxActivity, icon)?.mutate()?.apply { setTint(ink) }
                setShowAsAction(MenuItem.SHOW_AS_ACTION_IF_ROOM)
            }
            add(MENU_BULK_ARCHIVE, R.string.action_archive, R.drawable.ic_archive)
            add(MENU_BULK_MOVE, R.string.action_move, R.drawable.ic_move)
            add(MENU_BULK_JUNK, R.string.action_junk, R.drawable.ic_spam)
            add(MENU_BULK_DELETE, R.string.action_delete, R.drawable.ic_delete)
            // Snoozing again from Snoozed only moves the wake time; the row would wrongly vanish.
            if (specialFolderOf(currentFolder) != SpecialFolder.SNOOZED) {
                add(MENU_BULK_SNOOZE, R.string.action_snooze, R.drawable.ic_snooze)
            }
            // Overflow: no undo bar, they are server first like the detail screen's button.
            menu.add(0, MENU_BULK_MARK_READ, MENU_BULK_MARK_READ, R.string.action_mark_read)
            menu.add(0, MENU_BULK_MARK_UNREAD, MENU_BULK_MARK_UNREAD, R.string.action_mark_unread)
            return true
        }

        override fun onPrepareActionMode(mode: ActionMode, menu: Menu): Boolean = false

        override fun onActionItemClicked(mode: ActionMode, item: MenuItem): Boolean {
            // The whole list, not the visible tab: a row selected under another tab is still selected.
            val chosen = (searchResults ?: allEmails).filter { it.id in selectedIds }
                // Pinned now: Move answers later, when the screen may show another folder.
                .map { it.copy(folder = it.sourceFolder()) }
            when (item.itemId) {
                MENU_BULK_ARCHIVE -> submitRowsAction(chosen, getString(R.string.action_archive), MailAction.ARCHIVE)
                MENU_BULK_JUNK -> submitRowsAction(chosen, getString(R.string.action_junk), MailAction.SPAM)
                MENU_BULK_DELETE -> submitRowsAction(chosen, getString(R.string.action_delete), MailAction.DELETE)
                MENU_BULK_MARK_READ -> chosen.filter { it.status == "unread" }.forEach { setReadState(it, read = true) }
                MENU_BULK_MARK_UNREAD -> chosen.filter { it.status != "unread" }.forEach { setReadState(it, read = false) }
                MENU_BULK_SNOOZE -> {
                    val pick = snoozePickerForTest ?: { then -> pickSnoozeTime(this@InboxActivity, then) }
                    pick { wakeAt ->
                        submitRowsAction(chosen, getString(R.string.action_snooze), MailAction.SNOOZE, wakeAt = wakeAt)
                    }
                }
                MENU_BULK_MOVE -> {
                    val pick = moveTargetPickerForTest
                        ?: { from, then -> pickMoveTarget(this@InboxActivity, mailRepository, ioExecutor, from, then) }
                    pick(currentFolder) { target ->
                        submitRowsAction(chosen, getString(R.string.action_move), MailAction.MOVE, target)
                    }
                }
                else -> return false
            }
            mode.finish()
            return true
        }

        override fun onDestroyActionMode(mode: ActionMode) {
            selectionMode = null
            selectedIds.clear()
            adapter.setSelection(emptySet())
        }
    }

    /** [submitRowAction] for several rows: one relay call per source folder. */
    private fun submitRowsAction(
        emails: List<Email>,
        label: String,
        action: MailAction,
        target: String? = null,
        wakeAt: java.time.Instant? = null,
    ) {
        if (emails.isEmpty()) return
        // Grouped now, not when the timer fires: by then the screen may show another folder.
        val byFolder = emails.groupBy { it.sourceFolder() }
        // As for one row: the session and account at the tap, not when Undo lets the action go.
        val account = shownAccount
        val session = ProcessState.generation()
        holdForUndo(emails, label) {
            byFolder.forEach { (folder, rows) ->
                val claims = mailRepository.beginRemovals(rows.map { it.id }, folder, session)
                val dropped = { claims.forEach(mailRepository::abandon) }
                MailBackgroundExecutor.submitReporting(this, label, onDropped = dropped) {
                    // Whatever the outcome: a partial failure can still have applied some rows.
                    mailRepository.mutateAll(action, claims, target, account, wakeAt).also { runOnUiThread { recountUnread() } }
                }
            }
        }
    }

    /** Hides [emails] at once and runs [send] when the Undo bar times out or is swiped away, or at
     *  [onStop], unless Undo is tapped first. The server is not asked anything until then. */
    private fun holdForUndo(emails: List<Email>, label: String, send: () -> Unit) {
        heldActions.hold(emails) {
            val keys = emails.map { it.rowKey() }.toSet()
            allEmails = allEmails.filter { it.rowKey() !in keys }
            searchResults = searchResults?.filter { it.rowKey() !in keys }
            rebuildTabs(allEmails)
            renderFilteredEmails()
            send()
        }
        rebuildTabs(allEmails)
        renderFilteredEmails()
        // One bar for everything held: the new bar replaces the last, and its Undo covers both.
        val rows = heldActions.heldEmails().size
        val message = if (heldActions.heldCount() == 1) {
            resources.getQuantityString(R.plurals.undo_message, rows, label, rows)
        } else {
            resources.getQuantityString(R.plurals.undo_message_several, rows, rows)
        }
        undoBar = Snackbar.make(recyclerView, message, UNDO_WINDOW_MS.toInt())
            .apply { if (bottomNav is BottomNavigationView && bottomNav.isVisible) anchorView = bottomNav }
            .setAction(R.string.undo) {
                if (heldActions.undoAll()) {
                    rebuildTabs(allEmails)
                    renderFilteredEmails()
                }
            }
            .addCallback(object : Snackbar.Callback() {
                override fun onDismissed(transientBottomBar: Snackbar?, event: Int) =
                    onUndoBarDismissed(transientBottomBar, event)
            })
            .also { applySnackbarTheme(this, it) }
            .also { it.show() }
    }

    /** Only the bar on screen speaks for what is held: a replaced bar can still time out late. */
    private fun onUndoBarDismissed(bar: Snackbar?, event: Int) {
        val current = bar != null && bar === undoBar
        if (current) undoBar = null
        if (commitsOnDismiss(event, current)) heldActions.flush()
    }

    @androidx.annotation.VisibleForTesting
    internal fun undoBarForTest(): Snackbar? = undoBar

    /** Delivers a dismissal as Android would, including one from a bar already replaced. */
    @androidx.annotation.VisibleForTesting
    internal fun dismissUndoBarForTest(bar: Snackbar?, event: Int) = onUndoBarDismissed(bar, event)

    private fun showFolderPickerPopup(anchor: View) {
        val popupMenu = PopupMenu(this, anchor)
        val unread = unreadByFolder
        popupMenu.menu.add(0, 0, 0, withUnread(getString(R.string.nav_inbox), unread["INBOX"] ?: 0)).isChecked =
            currentFolder == "INBOX"
        popupMenu.menu.add(0, 1, 1, withUnread(getString(R.string.nav_junk), unread["Junk"] ?: 0)).isChecked =
            currentFolder == "Junk"
        popupMenu.menu.add(0, 2, 2, withUnread(getString(R.string.nav_trash), unread["Trash"] ?: 0)).isChecked =
            currentFolder == "Trash"
        val archiveUnread = KeywordTabs.unreadInFolderTree(unread, ARCHIVE_PARENT_FOLDER)
        popupMenu.menu.add(0, 3, 3, withUnread(getString(R.string.nav_archive), archiveUnread)).isChecked =
            currentFolder == ARCHIVE_PARENT_FOLDER || currentFolder.startsWith("$ARCHIVE_PARENT_FOLDER/")
        popupMenu.menu.add(0, 4, 4, getString(SpecialFolder.SENT.label)).isChecked =
            specialFolderOf(currentFolder) == SpecialFolder.SENT
        popupMenu.menu.add(0, 5, 5, getString(SpecialFolder.DRAFTS.label)).isChecked =
            specialFolderOf(currentFolder) == SpecialFolder.DRAFTS
        popupMenu.menu.add(0, 7, 6, getString(SpecialFolder.SNOOZED.label)).isChecked =
            specialFolderOf(currentFolder) == SpecialFolder.SNOOZED
        popupMenu.menu.setGroupCheckable(0, true, true)
        // Its own group: an action, not a radio choice.
        popupMenu.menu.add(1, 6, 7, getString(R.string.nav_all_folders))
        popupMenu.menu.add(1, 8, 8, getString(R.string.nav_scheduled))

        popupMenu.setOnMenuItemClickListener { menuItem ->
            val folder = when (menuItem.itemId) {
                0 -> "INBOX"
                1 -> "Junk"
                2 -> "Trash"
                3 -> {
                    fetchAndShowArchiveSubfolders(anchor)
                    return@setOnMenuItemClickListener true
                }
                4 -> {
                    openSpecialFolder(SpecialFolder.SENT)
                    return@setOnMenuItemClickListener true
                }
                5 -> {
                    openSpecialFolder(SpecialFolder.DRAFTS)
                    return@setOnMenuItemClickListener true
                }
                7 -> {
                    openSpecialFolder(SpecialFolder.SNOOZED)
                    return@setOnMenuItemClickListener true
                }
                8 -> {
                    startActivity(Intent(this, ScheduledActivity::class.java))
                    return@setOnMenuItemClickListener true
                }
                6 -> {
                    foldersLauncher.launch(FoldersActivity.intentFor(this, open = currentFolder))
                    return@setOnMenuItemClickListener true
                }
                else -> return@setOnMenuItemClickListener false
            }
            switchFolder(folder)
            true
        }
        popupMenu.show()
    }

    private fun fetchAndShowArchiveSubfolders(anchor: View) {
        ioExecutor.execute {
            val outcome = mailRepository.listFolders(ARCHIVE_PARENT_FOLDER)
            runOnUiThread {
                if (outcome is MailOutcome.Success) {
                    showArchiveSubfoldersPopup(anchor, outcome.value.folders)
                } else {
                    val errorMessage = outcome.userFacingMessage()
                    if (errorMessage != null) {
                        Toast.makeText(this, errorMessage, Toast.LENGTH_LONG).show()
                    }
                }
            }
        }
    }

    /** The account names these folders, not us: "Sent Items", "INBOX.Sent". */
    private fun openSpecialFolder(kind: SpecialFolder) {
        ioExecutor.execute {
            val outcome = mailRepository.listFolders(null)
            runOnUiThread {
                if (outcome !is MailOutcome.Success) {
                    outcome.userFacingMessage()?.let { Toast.makeText(this, it, Toast.LENGTH_LONG).show() }
                    return@runOnUiThread
                }
                val path = specialFolderPath(outcome.value.folders, kind)
                if (path == null) {
                    val message = getString(R.string.special_folder_missing, getString(kind.label))
                    Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
                } else {
                    switchFolder(path)
                }
            }
        }
    }

    private fun showArchiveSubfoldersPopup(anchor: View, folders: List<FolderInfo>) {
        if (folders.isEmpty()) {
            Toast.makeText(this, R.string.no_archive_folders, Toast.LENGTH_SHORT).show()
            return
        }
        val popupMenu = PopupMenu(this, anchor)
        folders.forEachIndexed { index, folder ->
            val label = withUnread(folder.path.substringAfterLast('/'), unreadByFolder[folder.path] ?: 0)
            popupMenu.menu.add(0, index, index, label).isChecked =
                currentFolder == folder.path
        }
        popupMenu.menu.setGroupCheckable(0, true, true)
        popupMenu.setOnMenuItemClickListener { menuItem ->
            val folder = folders.getOrNull(menuItem.itemId) ?: return@setOnMenuItemClickListener false
            switchFolder(folder.path)
            true
        }
        popupMenu.show()
    }

    private fun setupBottomNav() {
        fun openFolderPickerFromTab() {
            val anchor = bottomNav.findViewById<View>(R.id.nav_inbox) ?: bottomNav
            showFolderPickerPopup(anchor)
        }

        setupPrimaryNavigation(this, bottomNav, R.id.nav_inbox, ::openFolderPickerFromTab)
    }

    private fun setupSwipeGestures() {
        // The active half's status colours; a theme change recreates this screen, so they are current.
        val palette = getStoredThemePalette(this)
        val archiveColor = Color.parseColor(palette.warning)
        val deleteColor = Color.parseColor(palette.danger)
        val iconSize = (24 * resources.displayMetrics.density).toInt()
        val iconMargin = (16 * resources.displayMetrics.density).toInt()
        val archiveIcon = ContextCompat.getDrawable(this, R.drawable.ic_archive)?.mutate()?.apply {
            setTint(readableOn(archiveColor))
        }
        val deleteIcon = ContextCompat.getDrawable(this, R.drawable.ic_delete)?.mutate()?.apply {
            setTint(readableOn(deleteColor))
        }
        // Rounded on the row's own corners so no sharp corner pokes out from behind the card.
        val cardRadius = resources.getDimension(R.dimen.card_corner_radius)
        val deleteBackground = android.graphics.drawable.GradientDrawable().apply {
            setColor(deleteColor)
            cornerRadii = floatArrayOf(cardRadius, cardRadius, 0f, 0f, 0f, 0f, cardRadius, cardRadius)
        }
        val archiveBackground = android.graphics.drawable.GradientDrawable().apply {
            setColor(archiveColor)
            cornerRadii = floatArrayOf(0f, 0f, cardRadius, cardRadius, cardRadius, cardRadius, 0f, 0f)
        }

        val itemTouchHelper = ItemTouchHelper(object : ItemTouchHelper.SimpleCallback(
            0,
            ItemTouchHelper.LEFT or ItemTouchHelper.RIGHT
        ) {
            // No swipes in selection mode, nor on the "Load older mail" footer.
            override fun getSwipeDirs(recyclerView: RecyclerView, viewHolder: RecyclerView.ViewHolder): Int =
                if (selectionMode != null || viewHolder.bindingAdapter !== adapter) 0 else super.getSwipeDirs(recyclerView, viewHolder)

            override fun onMove(
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                target: RecyclerView.ViewHolder
            ): Boolean = false


            override fun onChildDraw(
                c: Canvas,
                recyclerView: RecyclerView,
                viewHolder: RecyclerView.ViewHolder,
                dX: Float,
                dY: Float,
                actionState: Int,
                isCurrentlyActive: Boolean
            ) {
                if (actionState == ItemTouchHelper.ACTION_STATE_SWIPE) {
                    val itemView = viewHolder.itemView
                    val iconTop = itemView.top + (itemView.height - iconSize) / 2
                    val iconBottom = iconTop + iconSize

                    when {
                        dX > 0 -> {
                            deleteBackground.setBounds(
                                itemView.left, itemView.top, itemView.left + dX.toInt(), itemView.bottom
                            )
                            deleteBackground.draw(c)
                            if (dX > iconSize + iconMargin * 2) {
                                val iconLeft = itemView.left + iconMargin
                                deleteIcon?.setBounds(iconLeft, iconTop, iconLeft + iconSize, iconBottom)
                                deleteIcon?.draw(c)
                            }
                        }
                        dX < 0 -> {
                            archiveBackground.setBounds(
                                itemView.right + dX.toInt(), itemView.top, itemView.right, itemView.bottom
                            )
                            archiveBackground.draw(c)
                            if (-dX > iconSize + iconMargin * 2) {
                                val iconRight = itemView.right - iconMargin
                                archiveIcon?.setBounds(iconRight - iconSize, iconTop, iconRight, iconBottom)
                                archiveIcon?.draw(c)
                            }
                        }
                    }
                }
                super.onChildDraw(c, recyclerView, viewHolder, dX, dY, actionState, isCurrentlyActive)
            }

            override fun onSwiped(viewHolder: RecyclerView.ViewHolder, direction: Int) {
                val position = viewHolder.bindingAdapterPosition
                if (viewHolder.bindingAdapter !== adapter || position < 0 || position >= adapter.itemCount) return
                val email = adapter.getEmailAt(position)
                when (direction) {
                    ItemTouchHelper.LEFT ->
                        submitRowAction(email, getString(R.string.action_archive), mailRepository::archive)
                    ItemTouchHelper.RIGHT ->
                        submitRowAction(email, getString(R.string.action_delete), mailRepository::delete)
                }
            }
        })
        itemTouchHelper.attachToRecyclerView(recyclerView)
    }

    /** Hides the row now and lets the IMAP call finish on its own once the undo window closes:
     *  waiting for the network round trip before updating the list is what made swipes feel slow.
     *
     *  [sourceFolder] is read HERE rather than inside the closure. The worker runs after the swipe
     *  returns, and by then the screen — and [currentFolder] with it — may be showing a different
     *  mailbox, in which the same IMAP UID names a different message. */
    private fun submitRowAction(
        email: Email,
        label: String,
        mutate: RowMutation,
    ) {
        val sourceFolder = email.sourceFolder()
        // Same reasoning as sourceFolder: the row belongs to the account it was painted under, and
        // to the session current at the swipe, however long Undo holds it.
        val account = shownAccount
        val session = ProcessState.generation()
        // (folder, id): a Retry tapped after switching folders must not hide another folder's UID.
        fun isTheRow(row: Email) = row.id == email.id && row.sourceFolder() == sourceFolder
        val index = allEmails.indexOfFirst(::isTheRow)
        holdForUndo(listOf(email), label) {
            val claim = mailRepository.beginRemoval(email.id, sourceFolder, session)
            // Decided on the worker: reading the pairing is disk and crypto. Until the next repaint
            // [shownAccount] still names the old account, so it cannot answer this alone.
            val pairingChanged = java.util.concurrent.atomic.AtomicBoolean(false)
            val onFailure = { reason: String ->
                restoreFailedRow(email, sourceFolder, account, session, pairingChanged.get(), index, label, reason, mutate)
            }
            MailBackgroundExecutor.submitReporting(this, label, onFailure, onDropped = { mailRepository.abandon(claim) }) {
                rowActionObserverForTest?.invoke(email.id, sourceFolder)
                // [mutate] takes the folder through the claim: it has no way to reach for currentFolder.
                mutate(claim, account).also {
                    if (it is MailOutcome.Success) runOnUiThread { recountUnread() }
                    val active = activeAccountForTest?.invoke() ?: mailRepository.currentAccount()
                    pairingChanged.set(account != active)
                }
            }
        }
    }

    /** Puts a row whose action failed back where it was, with Retry. False once this screen is
     *  gone, so the executor falls back to its toast. An outcome from an earlier account is
     *  dropped: neither its row nor a Retry belongs on this one. */
    private fun restoreFailedRow(
        email: Email,
        sourceFolder: String,
        account: MailAccount?,
        session: Long,
        pairingChanged: Boolean,
        index: Int,
        label: String,
        reason: String,
        mutate: RowMutation,
    ): Boolean {
        if (isFinishing || isDestroyed) return false
        fun stillOurs() = !pairingChanged && ProcessState.isCurrent(session) && account == shownAccount
        if (!stillOurs()) {
            rowActionDroppedForTest?.invoke()
            return true
        }
        if (sourceFolder == currentFolder && allEmails.none { it.id == email.id }) {
            allEmails = allEmails.toMutableList().apply { add(index.coerceIn(0, size), email) }
            rebuildTabs(allEmails)
            renderFilteredEmails()
        }
        Snackbar.make(recyclerView, getString(R.string.mail_action_failed, label, reason), Snackbar.LENGTH_LONG)
            .setAction(R.string.action_retry) { if (stillOurs()) submitRowAction(email, label, mutate) }
            // Above the phone's bottom bar; the w600dp rail runs the full height beside the list.
            .apply { if (bottomNav is BottomNavigationView && bottomNav.isVisible) anchorView = bottomNav }
            .also { applySnackbarTheme(this, it) }
            .show()
        rowActionFailureShownForTest?.invoke()
        return true
    }

    /** An id names a message only within its folder. */
    private fun Email.rowKey(): Pair<String, String> = sourceFolder() to id

    @androidx.annotation.VisibleForTesting
    internal fun setFolderForTest(folder: String, tab: String) {
        currentFolder = folder
        selectedTab = tab
        if (::bottomNav.isInitialized) {
            applyFolderTitle()
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun currentFolderForTest(): String = currentFolder

    @androidx.annotation.VisibleForTesting
    internal fun allEmailsForTest(): List<Email> = allEmails

    @androidx.annotation.VisibleForTesting
    internal fun unreadByFolderForTest(): Map<String, Int> = unreadByFolder

    @androidx.annotation.VisibleForTesting
    internal fun refreshForTest() = refreshInbox()

    /** Seeds the list the way a refresh would. */
    @androidx.annotation.VisibleForTesting
    internal fun setEmailsForTest(emails: List<Email>) {
        allEmails = emails
        renderFilteredEmails()
    }

    /** The whole of what a right-swipe does. `onSwiped` above only resolves the row and picks a
     *  direction; everything that can own the wrong mailbox lives in [submitRowAction]. */
    @androidx.annotation.VisibleForTesting
    internal fun submitDeleteForTest(email: Email) =
        submitRowAction(email, getString(R.string.action_delete), mailRepository::delete)

    @androidx.annotation.VisibleForTesting
    internal fun selectedTabForTest(): String = selectedTab

    /** Marks [query] as the search on screen without sending it. */
    @androidx.annotation.VisibleForTesting
    internal fun beginSearchForTest(query: String) {
        searchQuery = query
    }

    @androidx.annotation.VisibleForTesting
    internal fun exitSearchForTest() = exitSearch()

    @androidx.annotation.VisibleForTesting
    internal fun shownEmailsForTest(): List<Email> = adapter.currentEmails()

    @androidx.annotation.VisibleForTesting
    internal fun toggleSelectedForTest(email: Email) = toggleSelected(email)

    @androidx.annotation.VisibleForTesting
    internal fun selectedIdsForTest(): Set<String> = selectedIds.toSet()

    @androidx.annotation.VisibleForTesting
    internal fun inSelectionModeForTest(): Boolean = selectionMode != null

    @androidx.annotation.VisibleForTesting
    internal fun switchFolderForTest(folder: String) = switchFolder(folder)

    /** Runs the selection bar's own Move handler, as tapping it would. */
    @androidx.annotation.VisibleForTesting
    internal fun bulkMoveForTest() {
        val mode = selectionMode ?: return
        selectionCallback.onActionItemClicked(mode, mode.menu.findItem(MENU_BULK_MOVE))
    }

    /** Runs the selection overflow's Mark read / Mark unread handler, as tapping it would. */
    @androidx.annotation.VisibleForTesting
    internal fun bulkMarkForTest(read: Boolean) {
        val mode = selectionMode ?: return
        selectionCallback.onActionItemClicked(mode, mode.menu.findItem(if (read) MENU_BULK_MARK_READ else MENU_BULK_MARK_UNREAD))
    }

    /** Runs the selection bar's own Snooze handler, as tapping it would. */
    @androidx.annotation.VisibleForTesting
    internal fun bulkSnoozeForTest() {
        val mode = selectionMode ?: return
        selectionCallback.onActionItemClicked(mode, mode.menu.findItem(MENU_BULK_SNOOZE))
    }

    @androidx.annotation.VisibleForTesting
    internal fun hasBulkSnoozeForTest(): Boolean = selectionMode?.menu?.findItem(MENU_BULK_SNOOZE) != null

    /** Null in production. Stands in for the snooze time picker. */
    @androidx.annotation.VisibleForTesting
    internal var snoozePickerForTest: ((then: (java.time.Instant) -> Unit) -> Unit)? = null

    /** Null in production. Stands in for the folder picker, which answers asynchronously. */
    @androidx.annotation.VisibleForTesting
    internal var moveTargetPickerForTest: ((from: String, then: (String) -> Unit) -> Unit)? = null

    @androidx.annotation.VisibleForTesting
    internal fun setShownAccountForTest(account: MailAccount?) {
        shownAccount = account
    }

    @androidx.annotation.VisibleForTesting
    internal fun setPendingScrollPositionForTest(position: Int) {
        pendingScrollPosition = position
    }

    @androidx.annotation.VisibleForTesting
    internal fun pendingScrollPositionForTest(): Int = pendingScrollPosition

    @androidx.annotation.VisibleForTesting
    internal fun pendingMessageIdForTest(): String? = pendingMessageId

    @androidx.annotation.VisibleForTesting
    internal fun clearPendingMessageForTest() {
        pendingMessageId = null
    }

    @androidx.annotation.VisibleForTesting
    internal fun firstVisiblePositionForTest(): Int =
        (recyclerView.layoutManager as LinearLayoutManager).findFirstVisibleItemPosition()

    /** Null while the pill is hidden. */
    @androidx.annotation.VisibleForTesting
    internal fun newMailPillTextForTest(): String? =
        newMailPill.text.toString().takeIf { newMailPill.visibility == View.VISIBLE }

    companion object {
        private const val REFRESH_INTERVAL_MS = 90_000L
        private const val PENDING_MESSAGE_POLL_INTERVAL_MS = 3_000L
        private const val PENDING_MESSAGE_TIMEOUT_MS = 30_000L
        private const val ARCHIVE_PARENT_FOLDER = "Archive"
        private const val MENU_SEARCH = 1
        private const val UNDO_WINDOW_MS = 5_000L
        private const val MENU_BULK_ARCHIVE = 10
        private const val MENU_BULK_MOVE = 11
        private const val MENU_BULK_JUNK = 12
        private const val MENU_BULK_DELETE = 13
        private const val MENU_BULK_MARK_READ = 14
        private const val MENU_BULK_MARK_UNREAD = 15
        private const val MENU_BULK_SNOOZE = 16
        const val STATE_FOLDER = "inbox_folder"
        const val STATE_TAB = "inbox_tab"
        const val STATE_SCROLL = "inbox_scroll"
    }
}

internal fun inboxEmptyVisible(shown: Int, loadedFolder: String?, currentFolder: String): Boolean =
    shown == 0 && loadedFolder == currentFolder

/** Leaf names the server itself falls back on (`special_folders.go` `folderNameAliases`), in
 *  its preference order. */
internal enum class SpecialFolder(
    @androidx.annotation.StringRes val label: Int,
    val aliases: List<String>,
    /** The server names it itself, exactly, at the top level: anything else is the user's. */
    val exact: Boolean = false,
    /** RFC 6154 role the relay reports in [FolderInfo.special]; the only thing a localized name keeps. */
    val use: String? = null,
) {
    SENT(R.string.nav_sent, listOf("Sent", "Sent Items", "Sent Messages", "Sent Mail"), use = "sent"),
    DRAFTS(R.string.nav_drafts, listOf("Drafts", "Draft"), use = "drafts"),
    /** KyPost-Server's `SnoozedFolder` (`adapters/imap/snooze.go`), created on the first snooze. */
    SNOOZED(R.string.nav_snoozed, listOf("Snoozed"), exact = true),
}

/** Paths the relay flagged by role this process, so "Gesendet" still reads as Sent once opened. */
private val flaggedSpecialFolders = java.util.concurrent.ConcurrentHashMap<String, SpecialFolder>()

internal fun mailboxLeaf(path: String): String = path.split('/', '.').last().trim()

/** Only at the top level or directly under INBOX: `Archive/Sent` or `Projects/Drafts` is the
 *  user's own folder, not the account's. */
internal fun specialFolderOf(path: String): SpecialFolder? {
    flaggedSpecialFolders[path]?.let { return it }
    SpecialFolder.entries.firstOrNull { it.exact && path in it.aliases }?.let { return it }
    if (mailboxParent(path).let { it.isNotEmpty() && !it.equals("INBOX", ignoreCase = true) }) return null
    return SpecialFolder.entries.firstOrNull { kind ->
        !kind.exact && kind.aliases.any { it.equals(mailboxLeaf(path), ignoreCase = true) }
    }
}

internal fun resolveSpecialFolder(paths: List<String>, kind: SpecialFolder): String? =
    if (kind.exact) {
        kind.aliases.firstOrNull { it in paths }
    } else {
        kind.aliases.firstNotNullOfOrNull { alias -> paths.firstOrNull { mailboxLeaf(it).equals(alias, ignoreCase = true) } }
    }

/** The server's special-use flag first, the English aliases for servers that do not send one. */
internal fun specialFolderPath(folders: List<FolderInfo>, kind: SpecialFolder): String? {
    val flagged = kind.use?.let { use -> folders.firstOrNull { it.special == use }?.path }
    flagged?.let { flaggedSpecialFolders[it] = kind }
    return flagged ?: resolveSpecialFolder(folders.map { it.path }, kind)
}

/** Rows [new] puts above the first row [old] already had. Zero on a first load. */
internal fun newRowsAbove(old: List<Email>, new: List<Email>): Int {
    if (old.isEmpty()) return 0
    val oldIds = old.mapTo(HashSet()) { it.id }
    return new.takeWhile { it.id !in oldIds }.size
}

/** (claim, account) -> outcome; the account is checked when the request is built. */
private typealias RowMutation = (PendingMail, MailAccount?) -> MailOutcome<Unit>
