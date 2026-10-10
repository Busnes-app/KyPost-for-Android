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

    /** [forceFullResync] asks for since=0; the daily self-heal runs regardless of this flag. */
    fun refreshFolder(folder: String, limit: Int = 50, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {
        val outcome = relaySource.fetchInbox(folder, limit, forceFullResync)
        if (outcome is MailOutcome.Success) {
            val result = outcome.value
            // Order is the whole point: Room first, checkpoint second. Room and DataStore cannot
            // share a transaction, so a crash between them replays this window — upserts and
            // deletes are idempotent — whereas the old order dropped it.
            // Filter and write under the removal lock, so a confirmed removal lands before or after
            // the whole write, never between the filter and it.
            pending.serialized {
                reconcileFetchResult(
                    emailDao,
                    folder,
                    "relay",
                    result.copy(messages = result.messages.filterNot { (folder to it.id) in removed }),
                )
            }
            commitCheckpoint(folder, result.checkpoint)
        }
        return outcome
    }

    /** Takes an action's claim on the caller's thread, before the work is queued: the row shows
     *  hidden at once, and the action belongs to the session current now, not when a worker runs. */
    fun beginRemoval(id: String, folder: String): PendingMail = begin(id, folder, read = false)

    fun beginRead(id: String, folder: String): PendingMail = begin(id, folder, read = true)

    private fun begin(id: String, folder: String, read: Boolean): PendingMail {
        val claim = PendingMail(id, folder, ProcessState.generation(), read)
        (if (read) reading else removing)[folder to id] = claim.session
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
        (if (claim.read) reading else removing).remove(claim.folder to claim.id, claim.session)
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

    /** Server first, Room second; [cachedEmails] shows the row read from [beginRead] until the
     *  relay answers. */
    fun markRead(claim: PendingMail): MailOutcome<Unit> =
        perform(claim, MailAction.READ) { emailDao.updateStatus(claim.id, claim.folder, "read") }

    /** For a caller already on the thread that runs the action, with nothing queued between. */
    @androidx.annotation.VisibleForTesting
    internal fun markRead(id: String, folder: String): MailOutcome<Unit> = markRead(beginRead(id, folder))

    fun currentAccount(): MailAccount? = relaySource.currentAccount()

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
        var outcome: MailOutcome<Unit> = MailOutcome.Unauthorized("The session this action began in has ended")
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

    fun saveClientEncryptedDraft(draft: ClientEncryptedDraft): MailOutcome<Unit> =
        relaySource.saveClientEncryptedDraft(draft)

    fun send(draft: MailDraft): MailOutcome<MailSendOutcome> = relaySource.sendMail(draft)

    /** The client-custody send: this device already encrypted and signed, the relay only forwards. */
    fun sendClientEncrypted(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> =
        relaySource.sendClientEncrypted(message)

    fun listFolders(parent: String?): MailOutcome<FolderListResult> = relaySource.listFolders(parent)

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
    fun fetchBody(id: String, folder: String): MailOutcome<MailMessageBody> {
        val row = emailDao.getById(id, folder) ?: return relaySource.fetchMessageBody(id, folder)
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
            emailDao.updateBody(id, folder, fetched.value.html, fetched.value.bodyMode)
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
    /** Key -> the session generation the action started in, so a stale action clears only its own. */
    val removing: MutableMap<Pair<String, String>, Long> = ConcurrentHashMap()
    val reading: MutableMap<Pair<String, String>, Long> = ConcurrentHashMap()

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

/** HTTP 200 is transport success, not operation success: `/api/inbox/actions` answers 200 with the
 *  requested id in `failed[]` (Mobile_Mail_Relay.md Part 2). Only an id the relay actually
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
            preview = existing.preview,
            bodyMode = incoming.bodyMode.ifBlank { existing.bodyMode },
        )
    }
    emailDao.applyFolderDelta(
        folder = folder,
        upserts = newEntities + mergedEntities,
        removedIds = result.removedMessageIds,
        // Only a full window can say what is absent; cursor deltas omit unchanged mail and must not prune.
        pruneKeepIds = result.messages.map { it.id }.takeIf { result.isFullWindow },
    )
}

private fun <T> MailOutcome<T>.toUnitOutcome(): MailOutcome<Unit> = when (this) {
    is MailOutcome.Success -> MailOutcome.Success(Unit)
    is MailOutcome.NotConfigured -> this
    is MailOutcome.Unauthorized -> this
    is MailOutcome.ServiceUnavailable -> this
    is MailOutcome.UpstreamFailure -> this
    is MailOutcome.BadRequest -> this
    is MailOutcome.CertificateMismatch -> this
    is MailOutcome.ClientSideNeeded -> this
    is MailOutcome.PickupFallbackNeeded -> this
    is MailOutcome.ActionRejected -> this
    is MailOutcome.RateLimited -> this
}
