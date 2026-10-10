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
    pending: PendingMailActions = PendingMailActions(),
) {
    private val removing = pending.removing
    private val reading = pending.reading
    private val removed = pending.removed

    fun cachedEmails(folder: String): List<Email> = emailDao.getByFolder(folder)
        .filterNot { (folder to it.messageId).let { key -> key in removing || key in removed } }
        .map { row -> row.toUiEmail().let { if ((folder to it.id) in reading) it.copy(status = "read") else it } }

    /** [forceFullResync] asks for since=0; the daily self-heal runs regardless of this flag. */
    fun refreshFolder(folder: String, limit: Int = 50, forceFullResync: Boolean = false): MailOutcome<MailFetchResult> {
        val outcome = relaySource.fetchInbox(folder, limit, forceFullResync)
        if (outcome is MailOutcome.Success) {
            val result = outcome.value
            // Order is the whole point: Room first, checkpoint second. Room and DataStore cannot
            // share a transaction, so a crash between them replays this window — upserts and
            // deletes are idempotent — whereas the old order dropped it.
            reconcileFetchResult(
                emailDao,
                folder,
                "relay",
                result.copy(messages = result.messages.filterNot { (folder to it.id) in removed }),
            )
            commitCheckpoint(folder, result.checkpoint)
        }
        return outcome
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

    /** Server first, Room second; [cachedEmails] shows the row read while the call is in flight. */
    fun markRead(id: String, folder: String): MailOutcome<Unit> {
        val key = folder to id
        reading.add(key)
        try {
            val outcome = relaySource.performAction(MailAction.READ, listOf(id), folder).appliedTo(id)
            if (outcome is MailOutcome.Success) emailDao.updateStatus(id, folder, "read")
            return outcome
        } finally {
            reading.remove(key)
        }
    }

    fun archive(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.ARCHIVE, id, folder)

    fun spam(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.SPAM, id, folder)

    fun delete(id: String, folder: String): MailOutcome<Unit> = mutate(MailAction.DELETE, id, folder)

    fun move(id: String, folder: String, targetFolder: String): MailOutcome<Unit> =
        mutate(MailAction.MOVE, id, folder, targetFolder)

    /** The local row goes only when the relay says this id was processed — the message is gone from
     *  [folder] either way (deleted, or now living in another mailbox). [cachedEmails] hides it
     *  while the call is in flight and shows it again if the call fails. */
    private fun mutate(
        action: MailAction,
        id: String,
        folder: String,
        targetFolder: String? = null,
    ): MailOutcome<Unit> {
        val key = folder to id
        removing.add(key)
        try {
            val outcome = relaySource.performAction(action, listOf(id), folder, targetFolder).appliedTo(id)
            if (outcome is MailOutcome.Success) {
                removed.add(key)
                emailDao.deleteById(id, folder)
            }
            return outcome
        } finally {
            removing.remove(key)
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
class PendingMailActions : ProcessScopedState {
    val removing: MutableSet<Pair<String, String>> = ConcurrentHashMap.newKeySet()
    val reading: MutableSet<Pair<String, String>> = ConcurrentHashMap.newKeySet()

    /** Confirmed removals. An IMAP UID is never reused in its mailbox, so a refresh that read the
     *  window before the removal landed must not write the row back.
     *  ponytail: one entry per removal until the session ends; a UIDVALIDITY reset would hide a
     *  reused id until then. */
    val removed: MutableSet<Pair<String, String>> = ConcurrentHashMap.newKeySet()

    override fun resetForNewSession() {
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
