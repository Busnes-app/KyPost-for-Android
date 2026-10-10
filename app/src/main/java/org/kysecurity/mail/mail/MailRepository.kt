package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState
import org.kysecurity.mail.splitAddresses
import org.kysecurity.mail.data.EmailDao
import org.kysecurity.mail.data.EmailEntity
import org.kysecurity.mail.data.toEntity
import org.kysecurity.mail.data.toUiEmail
import java.util.concurrent.ConcurrentHashMap

/** The one synchronization boundary: [MailSource] returns facts, this decides when they — and the
 *  checkpoint that skips them next time — become durable. */
class MailRepository(
    private val emailDao: EmailDao,
    private val relaySource: MailSource,
    private val cursorProvider: MailCursorProvider,
    private val pending: PendingMailActions = PendingMailActions(),
) {
    private val removing = pending.removing
    private val reading = pending.reading
    private val removed = pending.removed

    fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder)
        .filterNot { (folder to it.messageId).let { key -> removing.containsKey(key) || key in removed } }
        .map { row -> row.toUiEmail().let { if (reading.containsKey(folder to it.id)) it.copy(status = "read") else it } }

    /** A confirmed removal stays gone: a fetch that read the folder before it landed must not write it back. */
    private fun notRemoved(folder: String, messages: List<Email>) = messages.filterNot { (folder to it.id) in removed }

    /** Unread rows per folder in the local cache: what this device holds, not a server total. */
    fun unreadCounts(): Map<String, Int> = emailDao.unreadCounts().associate { it.folder to it.unread }

    /** [forceFullResync] asks for since=0; the daily self-heal runs regardless of this flag. */
    fun refreshFolder(folder: String, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {
        val outcome = relaySource.fetchInbox(folder, WINDOW_LIMIT, forceFullResync)
        if (outcome !is MailOutcome.Success) return outcome
        val result = outcome.value
        // Fetched before anything is written, so "held" means held before this refresh.
        val (overflow, overflowFailure) =
            if (result.isDelta && result.hasMore) fetchOverflow(folder, result.nextBefore) else emptyList<Email>() to null
        // Nothing from a failed walk is stored, the window included: any row it left would count as
        // held, and a retry would stop at it and commit past the pages that never arrived.
        if (overflowFailure != null) return overflowFailure
        // Window and walk land together for the same reason. Then the checkpoint: Room and
        // DataStore cannot share a transaction, so a crash between them replays this fetch
        // (upserts and deletes are idempotent), whereas the other order dropped it.
        // Filter and write under the removal lock, so a confirmed removal lands before or after
        // the whole write, never between the filter and it.
        pending.serialized {
            emailDao.inTransaction {
                reconcileFetchResult(emailDao, folder, "relay", result.copy(messages = notRemoved(folder, result.messages)))
                reconcileOlderMail(emailDao, folder, "relay", notRemoved(folder, overflow))
            }
        }
        commitCheckpoint(folder, result.checkpoint)
        return outcome
    }

    /** More new mail arrived than the window holds: page down until reaching mail already held. */
    private fun fetchOverflow(folder: String, from: String?): Pair<List<Email>, MailOutcome<Nothing>?> {
        val held = emailDao.getIds(folder).toSet()
        val pages = mutableListOf<Email>()
        var before = from
        repeat(MAX_OVERFLOW_PAGES) {
            val at = before ?: return pages to MailOutcome.UpstreamFailure(OVERFLOW_UNREACHABLE)
            val page = relaySource.fetchOlder(folder, WINDOW_LIMIT, at)
            if (page !is MailOutcome.Success) return pages to page.failureOrNull()
            // This server announced overflow, so a page without hasMore contradicts it.
            val hasMore = page.value.hasMore ?: return pages to MailOutcome.UpstreamFailure(OVERFLOW_UNREACHABLE)
            pages += page.value.messages
            if (!hasMore || page.value.messages.any { it.id in held }) return pages to null
            before = page.value.nextBefore?.takeIf { it != at }
        }
        return pages to null
    }

    /** One page older than [frontier], or than the oldest row held when there is none yet. Null
     *  when the folder holds no row to page from. */
    fun loadOlderFrom(folder: String, frontier: String?): MailOutcome<MailPage>? {
        // A failed read is not an empty folder: report it, so the caller keeps offering a retry.
        val before = frontier ?: try {
            cachedEmails(folder).lastOrNull()?.id
        } catch (_: RuntimeException) {
            return MailOutcome.BadRequest(OLDER_MAIL_NOT_SAVED)
        } ?: return null
        return loadOlder(folder, before)
    }

    /** One page older than [before] into Room. The caller pages on from [MailPage.nextBefore]. */
    fun loadOlder(folder: String, before: String): MailOutcome<MailPage> {
        val outcome = relaySource.fetchOlder(folder, WINDOW_LIMIT, before)
        if (outcome !is MailOutcome.Success) return outcome
        // The server ignored before= and sent its newest window, which is not older mail.
        if (outcome.value.hasMore == null) return MailOutcome.BadRequest(OLDER_MAIL_UNSUPPORTED)
        // Room reports a full disk or I/O error as a RuntimeException (SQLiteFullException and kin).
        try {
            pending.serialized { reconcileOlderMail(emailDao, folder, "relay", notRemoved(folder, outcome.value.messages)) }
        } catch (_: RuntimeException) {
            return MailOutcome.BadRequest(OLDER_MAIL_NOT_SAVED)
        }
        return outcome
    }

    /** Takes an action's claim on the caller's thread, before the work is queued: the row shows
     *  hidden at once, and the action belongs to the session current now, not when a worker runs. */
    fun beginRemoval(id: String, folder: String, session: Long = ProcessState.generation()): PendingMail =
        begin(id, folder, read = false, session)

    fun beginRead(id: String, folder: String): PendingMail = begin(id, folder, read = true, ProcessState.generation())

    /** [session] is the generation when the user acted; a claim taken later (after an Undo window)
     *  passes the one it captured then. */
    private fun begin(id: String, folder: String, read: Boolean, session: Long): PendingMail {
        val claim = PendingMail(id, folder, session, read)
        (if (read) reading else removing)[folder to id] = claim
        return claim
    }

    /** For work that was never queued (scheduling refused): the row shows as it was. */
    fun abandon(claim: PendingMail) = release(claim)

    /** Called when a read overlay is dropped after a failure, so a list can repaint. A failed
     *  removal is not reported: the screen that hid the row decides whether it comes back. */
    fun setOverlayListener(listener: (() -> Unit)?) {
        pending.onOverlayDropped = listener
    }

    private fun release(claim: PendingMail, failed: Boolean = true) {
        (if (claim.read) reading else removing).remove(claim.folder to claim.id, claim)
        if (failed && claim.read) pending.onOverlayDropped?.invoke()
    }

    private fun commitCheckpoint(folder: String, checkpoint: MailCheckpoint?) {
        if (checkpoint == null) return
        if (checkpoint.cursor.isNotBlank()) {
            cursorProvider.saveCursor(checkpoint.subscriberId, folder, checkpoint.cursor)
        }
        if (checkpoint.wasFullResync) {
            cursorProvider.recordFullResync(checkpoint.subscriberId, folder)
        }
    }

    /** The open's read: server first, Room second; [cachedEmails] shows the row read from
     *  [beginRead] until the relay answers. */
    fun markRead(claim: PendingMail): MailOutcome<Unit> {
        var outcome: MailOutcome<Unit>? = null
        try {
            return setStatus(MailAction.READ, "read", claim.id, claim.folder, claim.session).also { outcome = it }
        } finally {
            release(claim, failed = outcome !is MailOutcome.Success)
        }
    }

    /** An explicit Mark read (the inbox selection): server first with no overlay, so the row
     *  repaints only once the relay confirms, like [markUnread]. [session] is the generation when
     *  the user acted. */
    fun markRead(id: String, folder: String, session: Long = ProcessState.generation()): MailOutcome<Unit> =
        setStatus(MailAction.READ, "read", id, folder, session)

    /** Server first, no overlay. A server without the action (pre-KyPost-Server #350) answers 400
     *  "unsupported action", which is returned for the caller to show. */
    fun markUnread(id: String, folder: String, session: Long = ProcessState.generation()): MailOutcome<Unit> =
        setStatus(MailAction.UNREAD, "unread", id, folder, session)

    /** Like [perform]: nothing is sent once [session] has ended, and Room is written only while it
     *  is current, under the reset's lock. */
    private fun setStatus(action: MailAction, status: String, id: String, folder: String, session: Long): MailOutcome<Unit> {
        if (!ProcessState.isCurrent(session)) return MailOutcome.Unauthorized(SESSION_ENDED)
        val outcome = relaySource.performAction(action, listOf(id), folder).appliedTo(id)
        if (outcome is MailOutcome.Success) pending.applyIfCurrent(session) { emailDao.updateStatus(id, folder, status) }
        return outcome
    }

    /** [account], when given, must still be the paired account when the request is built. */
    fun archive(claim: PendingMail, account: MailAccount? = null): MailOutcome<Unit> =
        mutate(MailAction.ARCHIVE, claim, account = account)

    fun spam(claim: PendingMail): MailOutcome<Unit> = mutate(MailAction.SPAM, claim)

    fun delete(claim: PendingMail, account: MailAccount? = null): MailOutcome<Unit> =
        mutate(MailAction.DELETE, claim, account = account)

    fun move(claim: PendingMail, targetFolder: String): MailOutcome<Unit> =
        mutate(MailAction.MOVE, claim, targetFolder)

    @androidx.annotation.VisibleForTesting
    internal fun archive(id: String, folder: String): MailOutcome<Unit> = archive(beginRemoval(id, folder))

    @androidx.annotation.VisibleForTesting
    internal fun spam(id: String, folder: String): MailOutcome<Unit> = spam(beginRemoval(id, folder))

    @androidx.annotation.VisibleForTesting
    internal fun delete(id: String, folder: String): MailOutcome<Unit> = delete(beginRemoval(id, folder))

    @androidx.annotation.VisibleForTesting
    internal fun move(id: String, folder: String, targetFolder: String): MailOutcome<Unit> =
        move(beginRemoval(id, folder), targetFolder)

    /** The local row goes only when the relay says this id was processed — the message is gone from
     *  its folder either way (deleted, or now living in another mailbox). */
    private fun mutate(
        action: MailAction,
        claim: PendingMail,
        targetFolder: String? = null,
        account: MailAccount? = null,
    ): MailOutcome<Unit> = perform(claim, action, targetFolder, account) {
        removed.add(claim.folder to claim.id)
        emailDao.deleteById(claim.id, claim.folder)
    }

    /** Sends [action] only while [claim]'s session is current, and applies [onSuccess] only if it
     *  still is, under the reset's lock: a success from an ended session names a folder and UID the
     *  next session may also hold. */
    private fun perform(
        claim: PendingMail,
        action: MailAction,
        targetFolder: String? = null,
        account: MailAccount? = null,
        onSuccess: () -> Unit,
    ): MailOutcome<Unit> {
        var outcome: MailOutcome<Unit> = MailOutcome.Unauthorized(SESSION_ENDED)
        try {
            if (!ProcessState.isCurrent(claim.session)) return outcome
            outcome = relaySource.performAction(action, listOf(claim.id), claim.folder, targetFolder, account)
                .appliedTo(claim.id)
            if (outcome is MailOutcome.Success) pending.applyIfCurrent(claim.session, onSuccess)
            return outcome
        } finally {
            release(claim, failed = outcome !is MailOutcome.Success)
        }
    }

    /** [beginRemoval] for several rows of one [folder], one session for all of them. */
    fun beginRemovals(
        ids: List<String>,
        folder: String,
        session: Long = ProcessState.generation(),
    ): List<PendingMail> = ids.map { beginRemoval(it, folder, session) }

    /** Several claims in one folder, one relay call. Drops only the rows the relay confirmed.
     *  `processed` is a count, so a total that `failed[]` does not account for confirms none.
     *  Like a single action: nothing is sent once the claims' session has ended, and a success
     *  applies only while it is current, under the reset's lock. */
    fun mutateAll(
        action: MailAction,
        claims: List<PendingMail>,
        targetFolder: String? = null,
        account: MailAccount? = null,
    ): MailOutcome<Unit> {
        val first = claims.firstOrNull() ?: return MailOutcome.Success(Unit)
        require(claims.all { it.folder == first.folder && it.session == first.session && !it.read })
        val folder = first.folder
        val ids = claims.map { it.id }
        var applied = false
        try {
            if (!ProcessState.isCurrent(first.session)) {
                return MailOutcome.Unauthorized(SESSION_ENDED)
            }
            val outcome = relaySource.performAction(action, ids, folder, targetFolder, account)
            if (outcome !is MailOutcome.Success) return outcome.toUnitOutcome()
            val failed = outcome.value.failed
            val confirmed = ids.filter { id -> failed.none { it.first == id } }
            if (outcome.value.processed != confirmed.size) {
                return MailOutcome.ActionRejected(ids.first(), "The server reported an incomplete change")
            }
            pending.applyIfCurrent(first.session) {
                confirmed.forEach {
                    removed.add(folder to it)
                    emailDao.deleteById(it, folder)
                }
                applied = true
            }
            val rejected = failed.firstOrNull() ?: return MailOutcome.Success(Unit)
            return MailOutcome.ActionRejected(rejected.first, "${failed.size} of ${ids.size} not changed: ${rejected.second}")
        } finally {
            claims.forEach { release(it, failed = !applied) }
        }
    }

    @androidx.annotation.VisibleForTesting
    internal fun mutateAll(
        action: MailAction,
        ids: List<String>,
        folder: String,
        targetFolder: String? = null,
    ): MailOutcome<Unit> = mutateAll(action, beginRemovals(ids, folder), targetFolder)

    fun saveClientEncryptedDraft(draft: ClientEncryptedDraft): MailOutcome<Unit> =
        relaySource.saveClientEncryptedDraft(draft)

    fun send(draft: MailDraft, account: MailAccount? = null): MailOutcome<MailSendOutcome> =
        relaySource.sendMail(draft, account)

    fun currentAccount(): MailAccount? = relaySource.currentAccount()

    /** The client-custody send: this device already encrypted and signed, the relay only forwards. */
    fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> =
        relaySource.sendClientEncrypted(message)

    fun listFolders(parent: String?): MailOutcome<FolderListResult> = relaySource.listFolders(parent)

    /** Not cached: results are a view of [folder], not its window, and must not prune it. */
    fun search(query: String, folder: String, limit: Int = 50): MailOutcome<List<Email>> =
        relaySource.searchMail(query, folder, limit)

    fun listAttachments(id: String, folder: String): MailOutcome<List<AttachmentInfo>> =
        relaySource.listAttachments(id, folder)

    fun downloadAttachment(id: String, folder: String, index: Int): MailOutcome<DownloadedAttachment> =
        relaySource.downloadAttachment(id, folder, index)

    /** Room caches the bodies that were opened, not the whole window: the inbox is fetched with
     *  `bodies=0`, so a row arrives with metadata and no body, and the body is fetched on open.
     *
     *  Blank means "not fetched yet" and is filled from the relay — EXCEPT when the row is
     *  `pgpEncrypted`, where blank is the client-protected shape and means the server genuinely has
     *  no plaintext to give under either protection mode. Fetching there would turn that state into
     *  BODY_UNAVAILABLE and drop the webmail handoff. Signed-but-not-encrypted mail is not
     *  `pgpEncrypted`, so it takes the fetch path and keeps the server's copy as the fallback for a
     *  signature this device cannot verify. */
    /** [knownTo]/[knownCc] are the caller's copy, for a message with no Room row (a search
     *  result): the relay's body endpoint carries no recipients. */
    fun fetchBody(
        id: String,
        folder: String,
        knownTo: List<String> = emptyList(),
        knownCc: List<String> = emptyList(),
    ): MailOutcome<MailMessageBody> {
        val row = emailDao.getById(id, folder) ?: return when (val fetched = relaySource.fetchMessageBody(id, folder)) {
            is MailOutcome.Success -> MailOutcome.Success(fetched.value.copy(toAddresses = knownTo, ccAddresses = knownCc))
            else -> fetched
        }
        // The cache is the only source of these: no relay response ever populates them — not the
        // inbox listing, and not /api/mail/body, which carries body and bodyMode alone. Taking the
        // response's empties is what makes Reply All reply to the sender alone.
        val to = splitAddresses(row.sentTo)
        val cc = splitAddresses(row.cc)
        val cached = row.body?.takeIf { it.isNotBlank() }
        if (cached == null && !row.pgpEncrypted) {
            val fetched = relaySource.fetchMessageBody(id, folder)
            // A failure stays a failure: the reader tells "the fetch failed" from "the server had
            // no body" to choose between an error and "No message body available."
            if (fetched !is MailOutcome.Success) return fetched
            // An older page carries no PGP flags, so a server-decrypted body cached on such a row
            // would escape clearServerDecryptedBodies. Out-of-window bodies are fetched per open.
            if (row.inWindow) emailDao.updateBody(id, folder, fetched.value.html, fetched.value.bodyMode)
            return MailOutcome.Success(fetched.value.copy(toAddresses = to, ccAddresses = cc))
        }
        return MailOutcome.Success(
            MailMessageBody(html = cached.orEmpty(), bodyMode = row.bodyMode, toAddresses = to, ccAddresses = cc),
        )
    }
}

/** (folder, id) keys, in memory only: Room holds what the relay confirmed, these hold what the user
 *  asked for and is waiting on, so the list neither waits on the network nor lies after a failure.
 *  Session-scoped: the next account's UIDs must not be hidden by this one's removals. */
/** An action's claim on one row: taken by [MailRepository.beginRemoval] or [MailRepository.beginRead]
 *  before the work is queued, carrying the session it began in. */
class PendingMail internal constructor(
    val id: String,
    val folder: String,
    val session: Long,
    internal val read: Boolean,
)

class PendingMailActions : ProcessScopedState {
    /** Key -> the latest claim on it, so a finishing action clears only its own: neither a stale
     *  session's nor an earlier open's read still queued behind a reopen's (ReadStateLane). */
    val removing: MutableMap<Pair<String, String>, PendingMail> = ConcurrentHashMap()
    val reading: MutableMap<Pair<String, String>, PendingMail> = ConcurrentHashMap()

    /** Confirmed removals. An IMAP UID is never reused in its mailbox, so a refresh that read the
     *  window before the removal landed must not write the row back.
     *  ponytail: one entry per removal until the session ends; a UIDVALIDITY reset would hide a
     *  reused id until then. */
    val removed: MutableSet<Pair<String, String>> = ConcurrentHashMap.newKeySet()

    /** See [MailRepository.setOverlayListener]. */
    @Volatile
    var onOverlayDropped: (() -> Unit)? = null

    /** Runs [apply] only if [token] is still the current session. Shares the reset's lock, so a
     *  completion either lands before the reset clears this session's state or not at all. */
    fun applyIfCurrent(token: Long, apply: () -> Unit) = synchronized(this) {
        if (ProcessState.isCurrent(token)) apply()
    }

    /** Refresh writes take the same lock as [applyIfCurrent]'s removals. */
    fun <T> serialized(block: () -> T): T = synchronized(this) { block() }

    override fun resetForNewSession() = synchronized(this) {
        removing.clear()
        reading.clear()
        removed.clear()
    }

    companion object {
        val process = PendingMailActions().also { ProcessState.register(it) }
    }
}

private const val SESSION_ENDED = "The session this action began in has ended"

/** The relay refuses `/api/inbox/actions` with more ids than this (server `maxInboxActionIDs`). */
const val MAX_ACTION_IDS = 500

/** HTTP 200 is transport success, not operation success: `/api/inbox/actions` answers 200 with the
 *  requested id in `failed[]` (docs/Mobile_Mail_Relay.md Part 2). Only an id the relay actually
 *  processed may be applied to the local cache. */
internal fun MailOutcome<MailActionOutcome>.appliedTo(id: String): MailOutcome<Unit> {
    if (this !is MailOutcome.Success) return toUnitOutcome()
    value.failed.firstOrNull { it.first == id }?.let { return MailOutcome.ActionRejected(id, it.second) }
    // `processed` is a count, not a list, so this is as close to "the id is in processed" as the
    // wire shape allows. Unknown counts as rejected: keeping a row the server may still hold costs
    // a redundant line in the list, whereas the other way round deletes mail that never moved.
    if (value.processed < 1) return MailOutcome.ActionRejected(id, "The server reported no change")
    return MailOutcome.Success(Unit)
}

internal fun reconcileFetchResult(emailDao: EmailDao, folder: String, mode: String, result: MailFetchResult) {
    // The inbox is fetched with bodies=0, so NO fetched entry carries a body and both write paths
    // below would otherwise blank the ones already fetched on open — @Upsert rewrites whole rows.
    // The daily self-heal is the one that bites: the relay answers `"delta": since > 0`, so its
    // since=0 window arrives as a snapshot and would wipe every opened body once a day.
    //
    // An absent body means "this response does not carry one", never "this message has none". An
    // IMAP UID is immutable, so a cached body cannot be stale for the id it is filed under; the
    // one thing that reuses ids is a UIDVALIDITY reset, which `replaceFolderSnapshot` still prunes.
    fun EmailEntity.keepingCachedBody(): EmailEntity {
        if (!body.isNullOrBlank()) return this
        val existing = emailDao.getById(messageId, folder) ?: return this
        return copy(body = existing.body, bodyMode = bodyMode.ifBlank { existing.bodyMode })
    }
    // A snapshot is the newest mail. An absent row older than all of it aged out unreported (a
    // forgotten cursor, an older relay); it still exists, so it leaves the window rather than Room.
    if (!result.isDelta || result.isFullWindow) {
        result.messages.mapNotNull { it.atUtc }.minOrNull()
            ?.let { oldest -> emailDao.markAgedOutBefore(folder, oldest, result.messages.map { it.id }) }
    }
    if (!result.isDelta) {
        emailDao.replaceFolderSnapshot(folder, result.messages.map { it.toEntity(folder, mode).keepingCachedBody() })
        return
    }
    val (updated, new) = result.messages.partition { it.id in result.updatedMessageIds }
    val newEntities = new.map { it.toEntity(folder, mode).keepingCachedBody() }
    // An "updated" entry never carries a body; with no existing row, skip rather than invent one.
    val mergedEntities = updated.mapNotNull { email ->
        val incoming = email.toEntity(folder, mode)
        val existing = emailDao.getById(incoming.messageId, folder) ?: return@mapNotNull null
        incoming.copy(
            body = existing.body,
            // "updated" rows carry no preview (KyPost-Server #351); keep the stored one, never for
            // encrypted mail.
            preview = if (incoming.pgpEncrypted) "" else existing.preview,
            bodyMode = incoming.bodyMode.ifBlank { existing.bodyMode },
        )
    }
    emailDao.applyFolderDelta(
        folder = folder,
        upserts = newEntities + mergedEntities,
        removedIds = result.removedMessageIds,
        // Only a full window can say what is absent; cursor deltas omit unchanged mail and must not prune.
        pruneKeepIds = result.messages.map { it.id }.takeIf { result.isFullWindow },
        agedOutIds = result.agedOutMessageIds,
    )
}

/** Mail older than the window. A held row keeps what only the window carries (body, attachment
 *  and PGP flags); a page refreshes just its read state and labels. */
internal fun reconcileOlderMail(emailDao: EmailDao, folder: String, mode: String, messages: List<Email>) {
    if (messages.isEmpty()) return
    emailDao.upsertAll(
        messages.map { email ->
            val incoming = email.toEntity(folder, mode)
            emailDao.getById(email.id, folder)
                ?.copy(status = incoming.status, label = incoming.label, keywordsJson = incoming.keywordsJson)
                ?: incoming.copy(inWindow = false)
        },
    )
}

/** One window size for every request: the relay keeps a cursor per `limit`, and a cursor sent
 *  with another limit is one that window never issued. */
internal const val WINDOW_LIMIT = 50

/** ponytail: overflow paging stops after this many pages and commits the cursor anyway, leaving
 *  anything older unlisted. Upgrade path: persist the paging frontier and resume from it. */
private const val MAX_OVERFLOW_PAGES = 20

private const val OVERFLOW_UNREACHABLE = "The server reported more new mail than it would page"

internal const val OLDER_MAIL_NOT_SAVED = "Couldn't save older mail on this device. Free up storage and try again."

internal const val OLDER_MAIL_UNSUPPORTED = "This server can't load older mail. Update KyPost Server to use this."

private fun <T> MailOutcome<T>.toUnitOutcome(): MailOutcome<Unit> = failureOrNull() ?: MailOutcome.Success(Unit)

/** A failure carries no value, so it fits any result type. */
private fun MailOutcome<*>.failureOrNull(): MailOutcome<Nothing>? = when (this) {
    is MailOutcome.Success -> null
    is MailOutcome.NotConfigured -> this
    is MailOutcome.Unauthorized -> this
    is MailOutcome.ServiceUnavailable -> this
    is MailOutcome.UpstreamFailure -> this
    is MailOutcome.BadRequest -> this
    is MailOutcome.CertificateMismatch -> this
    is MailOutcome.ClientSideNeeded -> this
    is MailOutcome.PickupFallbackNeeded -> this
    is MailOutcome.ActionRejected -> this
    is MailOutcome.ReplyThreadingRefused -> this
    is MailOutcome.RateLimited -> this
}
