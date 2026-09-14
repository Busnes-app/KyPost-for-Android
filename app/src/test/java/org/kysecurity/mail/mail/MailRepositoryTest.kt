package org.kysecurity.mail.mail

import org.kysecurity.mail.Email
import org.kysecurity.mail.data.EmailDao
import org.kysecurity.mail.data.EmailEntity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** In-memory fake implementing the (Room-generated-at-build-time) [EmailDao] interface directly,
 *  matching this repo's hand-rolled-fake test style rather than a mocking framework or Robolectric.
 *
 *  Keyed by (folder, messageId), exactly like the real table: a fake keyed on the id alone quietly
 *  reproduces the folder-collision bug it is supposed to catch. `EmailDaoFolderScopeTest` is the
 *  authority on the SQL itself. */
private class FakeEmailDao : EmailDao {
    val rows = linkedMapOf<Pair<String, String>, EmailEntity>()

    /** Throws on the next write, to stand in for "Room failed / storage filled / process died". */
    var failNextWrite = false

    private fun key(id: String, folder: String) = folder to id

    override fun getByFolder(folder: String): List<EmailEntity> = rows.values.filter { it.folder == folder }
    override fun upsertAll(emails: List<EmailEntity>) {
        if (failNextWrite) throw IllegalStateException("simulated Room failure")
        emails.forEach { rows[key(it.messageId, it.folder)] = it }
    }
    override fun updateStatus(id: String, folder: String, status: String) {
        rows[key(id, folder)]?.let { rows[key(id, folder)] = it.copy(status = status) }
    }
    override fun deleteById(id: String, folder: String) { rows.remove(key(id, folder)) }
    override fun clearAll() { rows.clear() }
    override fun getById(id: String, folder: String): EmailEntity? = rows[key(id, folder)]
    override fun pruneStaleInFolder(folder: String, keepIds: List<String>) {
        val keep = keepIds.toSet()
        rows.values.filter { it.folder == folder && it.messageId !in keep }
            .forEach { rows.remove(key(it.messageId, it.folder)) }
    }

    /** Mirrors the real query. The authority on the SQL itself is `EmailDaoLazyBodyTest`. */
    override fun updateBody(id: String, folder: String, body: String, bodyMode: String) {
        if (failNextWrite) throw IllegalStateException("simulated Room failure")
        rows[key(id, folder)]?.let { rows[key(id, folder)] = it.copy(body = body, bodyMode = bodyMode) }
    }

    /** Mirrors the real query's predicate. The authority on the SQL itself is
     *  `EmailDaoClearDecryptedTest`, which runs it against a real Room database. */
    override fun clearServerDecryptedBodies(): Int {
        val hits = rows.values.filter { it.pgpEncrypted && !it.body.isNullOrEmpty() }
        hits.forEach { rows[key(it.messageId, it.folder)] = it.copy(body = "", preview = "") }
        return hits.size
    }
}

private fun email(id: String, body: String? = "body-$id", status: String = "unread") = Email(
    id = id,
    subject = "Subject $id",
    sender = "sender@example.com",
    preview = body.orEmpty(),
    body = body,
    status = status,
    sourceMode = "relay",
)

private fun row(
    id: String,
    folder: String,
    body: String? = null,
    status: String = "unread",
    sentTo: String = "",
    cc: String = "",
    pgpEncrypted: Boolean = false,
) = EmailEntity(
    messageId = id,
    folder = folder,
    sender = "x",
    sentTo = sentTo,
    cc = cc,
    subject = "subject-$folder-$id",
    body = body,
    status = status,
    sourceMode = "relay",
    pgpEncrypted = pgpEncrypted,
)

private fun FakeEmailDao.put(entity: EmailEntity) {
    rows[entity.folder to entity.messageId] = entity
}

/** Records what was asked for and answers with whatever the test set up. Unused endpoints throw
 *  rather than returning a plausible-looking success. */
private class FakeMailSource(
    var fetchOutcome: MailOutcome<MailFetchResult> = MailOutcome.UpstreamFailure("not stubbed"),
    var actionOutcome: MailOutcome<MailActionOutcome> = MailOutcome.Success(MailActionOutcome(1, emptyList())),
) : MailSource {
    val actions = mutableListOf<Triple<MailAction, List<String>, String>>()

    override fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean) = fetchOutcome

    override fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String?,
    ): MailOutcome<MailActionOutcome> {
        actions += Triple(action, messageIds, mailbox)
        return actionOutcome
    }

    override fun listFolders(parent: String?) = unsupported()
    override fun createFolder(parent: String, name: String) = unsupported()
    override fun renameFolder(folder: String, name: String) = unsupported()
    override fun deleteFolder(folder: String) = unsupported()
    override fun saveDraft(draft: MailDraft) = unsupported()
    override fun saveClientEncryptedDraft(draft: ClientEncryptedDraft) = unsupported()
    override fun sendMail(draft: MailDraft) = unsupported()
    override fun sendClientEncrypted(message: ClientEncryptedMessage) = unsupported()
    /** Null keeps the old throwing behaviour, so tests asserting "must never reach the relay"
     *  still fail loudly rather than against a plausible-looking success. */
    var bodyOutcome: MailOutcome<MailMessageBody>? = null
    val bodyFetches = mutableListOf<Pair<String, String>>()

    override fun fetchMessageBody(messageId: String, folder: String): MailOutcome<MailMessageBody> {
        val stubbed = bodyOutcome ?: unsupported()
        bodyFetches += messageId to folder
        return stubbed
    }
    override fun listAttachments(messageId: String, folder: String) = unsupported()
    override fun downloadAttachment(messageId: String, folder: String, index: Int) = unsupported()

    private fun unsupported(): Nothing = throw UnsupportedOperationException("not used by these tests")
}

private class FakeCursorProvider : MailCursorProvider {
    val saved = mutableListOf<Triple<String, String, String>>()
    val fullResyncs = mutableListOf<Pair<String, String>>()

    override fun cursor(subscriberId: String, folder: String): String? =
        saved.lastOrNull { it.first == subscriberId && it.second == folder }?.third

    override fun saveCursor(subscriberId: String, folder: String, cursor: String) {
        saved += Triple(subscriberId, folder, cursor)
    }

    override fun shouldForceFullResync(subscriberId: String, folder: String) = false

    override fun recordFullResync(subscriberId: String, folder: String) {
        fullResyncs += subscriberId to folder
    }
}

private fun repository(
    dao: EmailDao,
    source: MailSource,
    cursors: MailCursorProvider = FakeCursorProvider(),
) = MailRepository(emailDao = dao, relaySource = source, cursorProvider = cursors)

class MailRepositoryTest {

    @Test
    fun nonDeltaResult_replacesFolderSnapshotWholesale() {
        val dao = FakeEmailDao()
        dao.put(row("stale", "INBOX"))

        val result = MailFetchResult(tabs = listOf("Work"), messages = listOf(email("m1")), isDelta = false)
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "m1"), dao.rows.keys)
    }

    @Test
    fun fullWindowDeltaResult_prunesIdsAbsentFromTheResponse() {
        val dao = FakeEmailDao()
        dao.put(row("deleted-on-web", "INBOX"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1")),
            isDelta = true,
            isFullWindow = true,
            removedMessageIds = emptyList(),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "m1"), dao.rows.keys)
    }

    @Test
    fun fullWindowDeltaResult_prunesButPreservesCachedBodyOfUpdatedEntries() {
        val dao = FakeEmailDao()
        dao.put(row("m1", "INBOX", body = "cached-body").copy(preview = "cached-preview"))
        dao.put(row("gone", "INBOX"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = true,
            isFullWindow = true,
            updatedMessageIds = setOf("m1"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "m1"), dao.rows.keys)
        assertEquals("cached-body", dao.getById("m1", "INBOX")?.body)
        assertEquals("cached-preview", dao.getById("m1", "INBOX")?.preview)
    }

    @Test
    fun partialDeltaResult_doesNotPruneUnmentionedRows() {
        val dao = FakeEmailDao()
        dao.put(row("untouched", "INBOX"))

        val result = MailFetchResult(tabs = emptyList(), messages = listOf(email("m1")), isDelta = true)
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "untouched", "INBOX" to "m1"), dao.rows.keys)
    }

    @Test
    fun deltaResult_insertsNewEntries() {
        val dao = FakeEmailDao()

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m1", body = "hello")),
            isDelta = true,
            updatedMessageIds = emptySet(),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("hello", dao.getById("m1", "INBOX")?.body)
    }

    @Test
    fun deltaResult_mergesUpdatedEntry_preservingCachedBodyAndPreview() {
        val dao = FakeEmailDao()
        dao.put(row("m2", "INBOX", body = "cached full body").copy(preview = "cached preview"))

        // An "updated" entry never carries a body (Mobile_Mail_Relay.md Part 5) — only status changed.
        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        val merged = dao.getById("m2", "INBOX")!!
        assertEquals("cached full body", merged.body)
        assertEquals("cached preview", merged.preview)
        assertEquals("read", merged.status)
    }

    @Test
    fun deltaResult_updatedEntryWithNoLocalCache_isSkippedRatherThanStoredBodyless() {
        val dao = FakeEmailDao()

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertNull(dao.getById("m2", "INBOX"))
    }

    @Test
    fun deltaResult_deletesRemovedIds() {
        val dao = FakeEmailDao()
        dao.put(row("m3", "INBOX"))

        val result = MailFetchResult(tabs = emptyList(), messages = emptyList(), isDelta = true, removedMessageIds = listOf("m3"))
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun deltaResult_mixOfNewUpdatedAndRemoved_allApplyTogether() {
        val dao = FakeEmailDao()
        dao.put(row("m2", "INBOX", body = "cached body").copy(preview = "cached preview"))
        dao.put(row("m3", "INBOX"))

        val result = MailFetchResult(
            tabs = listOf("Work"),
            messages = listOf(email("m1", body = "new body"), email("m2", body = null, status = "read")),
            isDelta = true,
            updatedMessageIds = setOf("m2"),
            removedMessageIds = listOf("m3"),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "m1", "INBOX" to "m2"), dao.rows.keys)
        assertEquals("new body", dao.getById("m1", "INBOX")?.body)
        assertEquals("cached body", dao.getById("m2", "INBOX")?.body)
    }

    // --- Folder-scoped identity: IMAP UIDs repeat across mailboxes -------------------------------

    @Test
    fun sameMessageIdInTwoFolders_areIndependentRows() {
        val dao = FakeEmailDao()
        dao.put(row("42", "Archive", body = "the archived one"))

        val result = MailFetchResult(tabs = emptyList(), messages = listOf(email("42", body = "the inbox one")), isDelta = false)
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("the archived one", dao.getById("42", "Archive")?.body)
        assertEquals("the inbox one", dao.getById("42", "INBOX")?.body)
    }

    @Test
    fun removalInOneFolder_doesNotDeleteTheSameIdInAnother() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        dao.put(row("42", "Archive"))

        val result = MailFetchResult(tabs = emptyList(), messages = emptyList(), isDelta = true, removedMessageIds = listOf("42"))
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertNull(dao.getById("42", "INBOX"))
        assertEquals(setOf("Archive" to "42"), dao.rows.keys)
    }

    @Test
    fun deleteInOneFolder_doesNotTouchTheSameIdInAnother() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        dao.put(row("42", "Archive"))
        val repo = repository(dao, FakeMailSource())

        assertTrue(repo.delete("42", "INBOX") is MailOutcome.Success)

        assertEquals(setOf("Archive" to "42"), dao.rows.keys)
    }

    @Test
    fun markReadInOneFolder_doesNotMarkTheSameIdReadInAnother() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        dao.put(row("42", "Archive"))
        val repo = repository(dao, FakeMailSource())

        repo.markRead("42", "INBOX")

        assertEquals("read", dao.getById("42", "INBOX")?.status)
        assertEquals("unread", dao.getById("42", "Archive")?.status)
    }

    @Test
    fun cachedBodyIsReadFromTheRequestedFolder_notWhicheverRowSharesTheId() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = "inbox body"))
        dao.put(row("42", "Archive", body = "archive body"))
        val repo = repository(dao, FakeMailSource())

        val outcome = repo.fetchBody("42", "Archive")

        assertEquals("archive body", (outcome as MailOutcome.Success).value.html)
    }

    /** Reply All's only source of recipients: nothing in a relay response ever populates them, so
     *  dropping them here made Reply All indistinguishable from Reply. */
    @Test
    fun cachedRecipientsAreParsedForReplyAll() {
        val dao = FakeEmailDao()
        dao.put(
            row(
                "42",
                "INBOX",
                body = "hello",
                sentTo = "me@example.com, Team <team@example.com>",
                cc = " watcher@example.com ,, WATCHER@example.com ",
            ),
        )
        val repo = repository(dao, FakeMailSource())

        val body = (repo.fetchBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals(listOf("me@example.com", "Team <team@example.com>"), body.toAddresses)
        assertEquals(listOf("watcher@example.com"), body.ccAddresses)
    }

    @Test
    fun noRecipientHeadersYieldEmptyListsRatherThanBlankAddresses() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = "hello"))
        val repo = repository(dao, FakeMailSource())

        val body = (repo.fetchBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals(emptyList<String>(), body.toAddresses)
        assertEquals(emptyList<String>(), body.ccAddresses)
    }

    /** A blank cached body must NOT be re-routed to the relay. `fetchMessageBody` is a hard-fail
     *  stub (the inbox listing carries bodies inline), so routing there turns the client-protected
     *  shape — pgpEncrypted with no body — into BODY_UNAVAILABLE and drops the webmail handoff.
     *  `FakeMailSource.fetchMessageBody` throws, so a regression fails loudly rather than quietly. */
    @Test
    fun clientProtectedRowIsServedFromCacheAndNeverRefetched() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = null, pgpEncrypted = true))
        val repo = repository(dao, FakeMailSource())

        val body = (repo.fetchBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals("", body.html)
    }

    /** The other half of the same rule: no row at all IS a cache miss, and must reach the source. */
    @Test
    fun missingRowFallsThroughToTheRelay() {
        val repo = repository(FakeEmailDao(), FakeMailSource())

        try {
            repo.fetchBody("42", "INBOX")
            throw AssertionError("expected the relay source to be consulted")
        } catch (expected: UnsupportedOperationException) {
            // FakeMailSource.fetchMessageBody: reaching it is the assertion.
        }
    }

    /** With bodies=0 the row arrives with metadata and no body, so a blank body is a cache miss to
     *  be filled — the opposite of the rule that held while /api/inbox carried bodies inline. */
    @Test
    fun blankCachedBodyIsFetchedFromTheRelay() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = null))
        val source = FakeMailSource().apply {
            bodyOutcome = MailOutcome.Success(
                MailMessageBody(html = "<p>hi</p>", bodyMode = "html", toAddresses = emptyList(), ccAddresses = emptyList()),
            )
        }

        val body = (repository(dao, source).fetchBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals("<p>hi</p>", body.html)
        assertEquals(listOf("42" to "INBOX"), source.bodyFetches)
    }

    /** Room becomes a cache of what was opened rather than a mirror of the window. Re-opening a
     *  message must not re-pay the round trip, and must still work with no network at all. */
    @Test
    fun aFetchedBodyIsCachedSoTheNextOpenNeedsNoNetwork() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = null))
        val source = FakeMailSource().apply {
            bodyOutcome = MailOutcome.Success(
                MailMessageBody(html = "<p>hi</p>", bodyMode = "html", toAddresses = emptyList(), ccAddresses = emptyList()),
            )
        }
        val repo = repository(dao, source)

        repo.fetchBody("42", "INBOX")
        val second = (repo.fetchBody("42", "INBOX") as MailOutcome.Success).value

        assertEquals("<p>hi</p>", second.html)
        assertEquals("html", second.bodyMode)
        assertEquals(1, source.bodyFetches.size)
    }

    /** /api/mail/body carries body and bodyMode only. Taking the recipients from it would overwrite
     *  the cached ones with empties, which is exactly what makes Reply All reply to the sender alone. */
    @Test
    fun aFetchedBodyKeepsTheCachedRecipientsForReplyAll() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = null, sentTo = "me@example.com", cc = "watcher@example.com"))
        val source = FakeMailSource().apply {
            bodyOutcome = MailOutcome.Success(
                MailMessageBody(html = "hi", bodyMode = "plain", toAddresses = emptyList(), ccAddresses = emptyList()),
            )
        }

        val body = (repository(dao, source).fetchBody("42", "INBOX") as MailOutcome.Success).value

        // The body came off the wire; the recipients did not, and must not have been overwritten
        // by the empties that came with it.
        assertEquals("hi", body.html)
        assertEquals(listOf("me@example.com"), body.toAddresses)
        assertEquals(listOf("watcher@example.com"), body.ccAddresses)
    }

    /** A failed fetch must stay a failure, not become "the server sent no body": the reader tells
     *  those apart to decide between an error and "No message body available." */
    @Test
    fun aFailedBodyFetchIsReportedRatherThanCachedAsEmpty() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX", body = null))
        val source = FakeMailSource().apply {
            bodyOutcome = MailOutcome.UpstreamFailure("imap down")
        }

        val outcome = repository(dao, source).fetchBody("42", "INBOX")

        assertTrue(outcome is MailOutcome.UpstreamFailure)
        assertNull(dao.getById("42", "INBOX")?.body)
    }

    /** The path the daily self-heal actually takes. The relay answers `"delta": since > 0`
     *  (server_inbox.go), so a since=0 window arrives with isDelta=false and goes through
     *  `replaceFolderSnapshot`, whose @Upsert rewrites whole rows. With bodies=0 that would drop
     *  every body the user had opened, once a day, on every folder. */
    @Test
    fun fullSnapshotWithoutBodies_keepsBodiesAlreadyFetchedOnOpen() {
        val dao = FakeEmailDao()
        dao.put(row("m1", "INBOX", body = "opened-earlier").copy(bodyMode = "html"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = false,
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("opened-earlier", dao.getById("m1", "INBOX")?.body)
        assertEquals("html", dao.getById("m1", "INBOX")?.bodyMode)
    }

    /** A snapshot still prunes: keeping a body must not keep a message the server no longer lists. */
    @Test
    fun fullSnapshotWithoutBodies_stillPrunesMessagesTheServerDropped() {
        val dao = FakeEmailDao()
        dao.put(row("m1", "INBOX", body = "opened-earlier"))
        dao.put(row("deleted-on-web", "INBOX", body = "also-opened"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = false,
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals(setOf("INBOX" to "m1"), dao.rows.keys)
    }

    /** The daily self-heal sends since=0, and the server labels EVERY message in that window
     *  `changeType: "new"` — not "updated" — so they take the new-entity path. With bodies=0 those
     *  entities carry no body, and Room's @Upsert replaces the whole row, which would drop every
     *  body the user had opened, once a day. An incoming entity with no body is missing one, never
     *  asserting the message has none: an IMAP UID is immutable, so a body never legitimately
     *  changes out from under a cached copy. */
    @Test
    fun fullResyncWithoutBodies_keepsBodiesAlreadyFetchedOnOpen() {
        val dao = FakeEmailDao()
        dao.put(row("m1", "INBOX", body = "opened-earlier").copy(bodyMode = "html"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = true,
            isFullWindow = true,
            updatedMessageIds = emptySet(),
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("opened-earlier", dao.getById("m1", "INBOX")?.body)
        assertEquals("html", dao.getById("m1", "INBOX")?.bodyMode)
    }

    /** The other half: a genuinely new message has no cached body to keep, and must not inherit
     *  one from a row that never existed. */
    @Test
    fun fullResyncWithoutBodies_storesNewMessagesBodyless() {
        val dao = FakeEmailDao()

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("m1", body = null)),
            isDelta = true,
            isFullWindow = true,
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertNull(dao.getById("m1", "INBOX")?.body)
    }

    /** The documented mitigation for a UIDVALIDITY reset (see `EmailEntity`): the daily since=0
     *  window rewrites every id it returns, so reused ids stop pointing at the old message. */
    @Test
    fun fullResyncOverwritesRowsWhoseIdsTheServerReused() {
        val dao = FakeEmailDao()
        dao.put(row("1", "INBOX", body = "pre-reset message"))

        val result = MailFetchResult(
            tabs = emptyList(),
            messages = listOf(email("1", body = "post-reset message")),
            isDelta = true,
            isFullWindow = true,
        )
        reconcileFetchResult(dao, "INBOX", "relay", result)

        assertEquals("post-reset message", dao.getById("1", "INBOX")?.body)
    }

    // --- Checkpoint durability -------------------------------------------------------------------

    @Test
    fun successfulRefresh_advancesTheCursorAndStampsTheFullResync() {
        val dao = FakeEmailDao()
        val cursors = FakeCursorProvider()
        val source = FakeMailSource(
            fetchOutcome = MailOutcome.Success(
                MailFetchResult(
                    tabs = emptyList(),
                    messages = listOf(email("m1")),
                    isDelta = true,
                    isFullWindow = true,
                    checkpoint = MailCheckpoint(subscriberId = "sub-1", cursor = "c-2", wasFullResync = true),
                ),
            ),
        )

        repository(dao, source, cursors).refreshFolder("INBOX")

        assertEquals(listOf(Triple("sub-1", "INBOX", "c-2")), cursors.saved)
        assertEquals(listOf("sub-1" to "INBOX"), cursors.fullResyncs)
        assertEquals("body-m1", dao.getById("m1", "INBOX")?.body)
    }

    /** The whole point of the ordering: an acknowledged cursor the relay would honour, for mail
     *  that never reached Room, means the server never sends those messages again. */
    @Test
    fun failedReconciliation_leavesTheCursorWhereItWas() {
        val dao = FakeEmailDao()
        dao.failNextWrite = true
        val cursors = FakeCursorProvider()
        cursors.saveCursor("sub-1", "INBOX", "c-1")
        cursors.saved.clear()
        val source = FakeMailSource(
            fetchOutcome = MailOutcome.Success(
                MailFetchResult(
                    tabs = emptyList(),
                    messages = listOf(email("m1")),
                    isDelta = true,
                    isFullWindow = true,
                    checkpoint = MailCheckpoint(subscriberId = "sub-1", cursor = "c-2", wasFullResync = true),
                ),
            ),
        )

        runCatching { repository(dao, source, cursors).refreshFolder("INBOX") }

        assertTrue("cursor must not advance past mail that never landed", cursors.saved.isEmpty())
        assertTrue("the resync stamp must not postpone the self-heal either", cursors.fullResyncs.isEmpty())
    }

    @Test
    fun failedFetch_doesNotTouchTheCursor() {
        val cursors = FakeCursorProvider()
        val source = FakeMailSource(fetchOutcome = MailOutcome.UpstreamFailure("IMAP is down"))

        repository(FakeEmailDao(), source, cursors).refreshFolder("INBOX")

        assertTrue(cursors.saved.isEmpty())
        assertTrue(cursors.fullResyncs.isEmpty())
    }

    @Test
    fun blankCursor_isNotPersistedOverAGoodOne() {
        val cursors = FakeCursorProvider()
        val source = FakeMailSource(
            fetchOutcome = MailOutcome.Success(
                MailFetchResult(
                    tabs = emptyList(),
                    messages = emptyList(),
                    isDelta = true,
                    checkpoint = MailCheckpoint(subscriberId = "sub-1", cursor = "", wasFullResync = false),
                ),
            ),
        )

        repository(FakeEmailDao(), source, cursors).refreshFolder("INBOX")

        assertTrue(cursors.saved.isEmpty())
    }

    // --- processed/failed is the operation's result, HTTP 200 is not -----------------------------

    @Test
    fun actionRejectedPerMessage_reportsFailureAndKeepsTheLocalRow() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(
            actionOutcome = MailOutcome.Success(
                MailActionOutcome(processed = 0, failed = listOf("42" to "mailbox is read-only")),
            ),
        )

        val outcome = repository(dao, source).archive("42", "INBOX")

        assertEquals("mailbox is read-only", (outcome as MailOutcome.ActionRejected).message)
        assertEquals("42", outcome.messageId)
        // Worded as the server's refusal, never as "couldn't reach the mail server" — the request
        // got there, and telling the user otherwise sends them to check their connection.
        assertEquals("mailbox is read-only", outcome.userFacingMessage())
        assertEquals(setOf("INBOX" to "42"), dao.rows.keys)
    }

    @Test
    fun actionAcknowledgedButNothingProcessed_isAFailure() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.Success(MailActionOutcome(processed = 0, failed = emptyList())))

        val outcome = repository(dao, source).delete("42", "INBOX")

        assertTrue(outcome is MailOutcome.ActionRejected)
        assertEquals(setOf("INBOX" to "42"), dao.rows.keys)
    }

    @Test
    fun actionProcessed_deletesTheLocalRow() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.Success(MailActionOutcome(processed = 1, failed = emptyList())))

        val outcome = repository(dao, source).delete("42", "INBOX")

        assertTrue(outcome is MailOutcome.Success)
        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun transportFailure_keepsTheLocalRowAndPropagatesTheOutcome() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.Unauthorized("re-pair"))

        val outcome = repository(dao, source).spam("42", "INBOX")

        assertTrue(outcome is MailOutcome.Unauthorized)
        assertEquals(setOf("INBOX" to "42"), dao.rows.keys)
    }

    @Test
    fun moveForwardsTheTargetMailboxAndOnlyDropsTheRowWhenProcessed() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(
            actionOutcome = MailOutcome.Success(MailActionOutcome(processed = 0, failed = listOf("42" to "no such mailbox"))),
        )

        val outcome = repository(dao, source).move("42", "INBOX", "Archive")

        assertTrue(outcome is MailOutcome.ActionRejected)
        assertEquals(MailAction.MOVE, source.actions.single().first)
        assertEquals(setOf("INBOX" to "42"), dao.rows.keys)
    }

    @Test
    fun markReadFailure_leavesTheRowUnread() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(
            actionOutcome = MailOutcome.Success(MailActionOutcome(processed = 0, failed = listOf("42" to "no such message"))),
        )

        val outcome = repository(dao, source).markRead("42", "INBOX")

        assertTrue(outcome is MailOutcome.ActionRejected)
        assertEquals("unread", dao.getById("42", "INBOX")?.status)
    }

    @Test
    fun markReadNetworkFailure_leavesTheRowUnread() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("relay is down"))

        val outcome = repository(dao, source).markRead("42", "INBOX")

        assertTrue(outcome is MailOutcome.ServiceUnavailable)
        assertEquals("unread", dao.getById("42", "INBOX")?.status)
    }

    @Test
    fun markReadSuccess_marksTheRowRead() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.Success(MailActionOutcome(processed = 1, failed = emptyList())))

        assertTrue(repository(dao, source).markRead("42", "INBOX") is MailOutcome.Success)
        assertEquals("read", dao.getById("42", "INBOX")?.status)
    }
}
