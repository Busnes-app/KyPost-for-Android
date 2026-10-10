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

    /** Runs at the start of [upsertAll], so a test can hold a refresh mid-write. */
    var beforeUpsert: (() -> Unit)? = null

    private fun key(id: String, folder: String) = folder to id

    override fun getByFolder(folder: String): List<EmailEntity> = rows.values.filter { it.folder == folder }
    override fun upsertAll(emails: List<EmailEntity>) {
        beforeUpsert?.invoke()
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

    /** Runs while the action is "on the wire", so a test can look at the cache mid-flight. */
    var duringAction: (() -> Unit)? = null

    override fun fetchInbox(mailbox: String, limit: Int, forceFullResync: Boolean) = fetchOutcome

    override fun performAction(
        action: MailAction,
        messageIds: List<String>,
        mailbox: String,
        targetMailbox: String?,
        account: MailAccount?,
    ): MailOutcome<MailActionOutcome> {
        actions += Triple(action, messageIds, mailbox)
        duringAction?.invoke()
        return actionOutcome
    }

    override fun currentAccount(): MailAccount? = null
    override fun listFolders(parent: String?) = unsupported()
    override fun createFolder(parent: String, name: String) = unsupported()
    override fun renameFolder(folder: String, name: String) = unsupported()
    override fun deleteFolder(folder: String) = unsupported()
    override fun saveDraft(draft: MailDraft) = unsupported()
    override fun saveClientEncryptedDraft(draft: ClientEncryptedDraft) = unsupported()
    override fun sendMail(draft: MailDraft, onCall: (okhttp3.Call) -> Unit) = unsupported()
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

    /** Some tests here run resetAll, which seals the process-wide draft cache; only take()
     *  unseals it. Left sealed, a later test class's save() silently does nothing. */
    @org.junit.After
    fun unsealTheDraftCache() {
        org.kysecurity.mail.ComposeDraftCache.take()
    }

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

    // --- optimistic display: in memory only, Room keeps confirmed state ---------------------------

    private fun snapshot(vararg ids: String) =
        MailOutcome.Success(MailFetchResult(tabs = emptyList(), messages = ids.map { email(it, body = null) }))

    @Test
    fun aRowWithAnActionInFlightIsHiddenEvenFromARefresh() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        dao.put(row("7", "INBOX"))
        val source = FakeMailSource(fetchOutcome = snapshot("42", "7"))
        val repository = repository(dao, source)
        var seen: List<String>? = null
        source.duringAction = {
            repository.refreshFolder("INBOX")
            seen = repository.cachedEmails("INBOX").map { it.id }
        }

        repository.archive("42", "INBOX")

        assertEquals(listOf("7"), seen)
    }

    @Test
    fun aFailedActionShowsTheRowAgain() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("relay is down"))
        val repository = repository(dao, source)

        repository.delete("42", "INBOX")

        assertEquals(listOf("42"), repository.cachedEmails("INBOX").map { it.id })
    }

    /** The refresh read the window before the delete landed and writes after it. An IMAP UID is
     *  never reused in its mailbox, so that row is stale and must not come back. */
    @Test
    fun aRefreshThatReadTheWindowBeforeADeleteDoesNotResurrectIt() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(fetchOutcome = snapshot("42", "7"))
        val repository = repository(dao, source)

        repository.delete("42", "INBOX")
        repository.refreshFolder("INBOX")

        assertEquals(setOf("INBOX" to "7"), dao.rows.keys)
        assertEquals(listOf("7"), repository.cachedEmails("INBOX").map { it.id })
    }

    @Test
    fun aDeltaThatReadTheWindowBeforeADeleteDoesNotResurrectIt() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource(
            fetchOutcome = MailOutcome.Success(
                MailFetchResult(tabs = emptyList(), messages = listOf(email("42", body = null)), isDelta = true),
            ),
        )
        val repository = repository(dao, source)

        repository.delete("42", "INBOX")
        repository.refreshFolder("INBOX")

        assertTrue(dao.rows.isEmpty())
    }

    @Test
    fun aRemovalIsScopedToItsFolder() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        dao.put(row("42", "Archive"))
        val repository = repository(dao, FakeMailSource())

        repository.delete("42", "INBOX")

        assertEquals(listOf("42"), repository.cachedEmails("Archive").map { it.id })
    }

    /** 3.9: the opened message must not stay bold while the read flag is on the wire. */
    @Test
    fun markReadInFlight_showsTheRowReadButLeavesRoomUnconfirmed() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val source = FakeMailSource()
        val repository = repository(dao, source)
        var shown: String? = null
        var stored: String? = null
        source.duringAction = {
            shown = repository.cachedEmails("INBOX").single().status
            stored = dao.getById("42", "INBOX")?.status
        }

        repository.markRead("42", "INBOX")

        assertEquals("read", shown)
        assertEquals("unread", stored)
    }

    /** UIDs are small integers in every account: the next account's INBOX 42 must not stay hidden. */
    @Test
    fun aSessionResetForgetsTheProcessWideRemovals() {
        PendingMailActions.process.removed += "INBOX" to "42"

        org.kysecurity.mail.ProcessState.resetAll()

        assertTrue(PendingMailActions.process.removed.isEmpty())
    }

    /** The session ends while the delete is on the wire, and the next one caches a message with the
     *  same folder and UID. The late success belongs to the old session and must touch nothing. */
    @Test
    fun aDeleteCompletingAfterASessionResetLeavesTheNextSessionsMessage() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val pending = PendingMailActions()
        val source = FakeMailSource()
        val repository = MailRepository(dao, source, FakeCursorProvider(), pending)
        source.duringAction = {
            org.kysecurity.mail.ProcessState.resetAll()
            pending.resetForNewSession()
            dao.rows.clear()
            dao.put(row("42", "INBOX", status = "unread").copy(subject = "next session"))
        }

        repository.delete("42", "INBOX")

        assertEquals("next session", dao.getById("42", "INBOX")?.subject)
        assertEquals(listOf("42"), repository.cachedEmails("INBOX").map { it.id })
        assertTrue(pending.removed.isEmpty())
    }

    @Test
    fun aMarkReadCompletingAfterASessionResetLeavesTheNextSessionsMessageUnread() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val pending = PendingMailActions()
        val source = FakeMailSource()
        val repository = MailRepository(dao, source, FakeCursorProvider(), pending)
        source.duringAction = {
            org.kysecurity.mail.ProcessState.resetAll()
            pending.resetForNewSession()
            dao.rows.clear()
            dao.put(row("42", "INBOX"))
        }

        repository.markRead("42", "INBOX")

        assertEquals("unread", dao.getById("42", "INBOX")?.status)
    }

    /** An old-session action finishing must not clear the same key for a newer action in flight. */
    @Test
    fun aStaleCompletionDoesNotClearANewerPendingRemoval() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val pending = PendingMailActions()
        val source = FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("down"))
        val repository = MailRepository(dao, source, FakeCursorProvider(), pending)
        source.duringAction = {
            org.kysecurity.mail.ProcessState.resetAll()
            pending.resetForNewSession()
            pending.removing["INBOX" to "42"] = org.kysecurity.mail.ProcessState.generation()
        }

        repository.delete("42", "INBOX")

        assertTrue(pending.removing.containsKey("INBOX" to "42"))
    }

    // --- actions begun on the caller's thread, run later on a worker ------------------------------

    /** Queued under the old account; by the time a worker runs it, the purge has reset the session
     *  and a replacement row with the same folder and UID is cached, while the old pairing is not
     *  yet cleared and would still authenticate a request. */
    @Test
    fun aDeleteQueuedBeforeAnAccountReplacementSendsNothingAndKeepsTheReplacementRow() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val pending = PendingMailActions()
        val source = FakeMailSource()
        val repository = MailRepository(dao, source, FakeCursorProvider(), pending)
        val queued = repository.beginRemoval("42", "INBOX")

        org.kysecurity.mail.ProcessState.advanceGeneration()
        org.kysecurity.mail.ProcessState.resetAll()
        pending.resetForNewSession()
        dao.rows.clear()
        dao.put(row("42", "INBOX").copy(subject = "replacement"))
        repository.delete(queued)

        assertTrue("the old session's request was sent", source.actions.isEmpty())
        assertEquals("replacement", dao.getById("42", "INBOX")?.subject)
        assertEquals(listOf("42"), repository.cachedEmails("INBOX").map { it.id })
        assertTrue(pending.removed.isEmpty())
    }

    /** The row is hidden from the moment the action is begun, not from when a worker picks it up. */
    @Test
    fun aRemovalBegunButNotYetRunIsHiddenFromARefresh() {
        val dao = FakeEmailDao()
        val repository = repository(dao, FakeMailSource(fetchOutcome = snapshot("42", "7")))

        repository.beginRemoval("42", "INBOX")
        repository.refreshFolder("INBOX")

        assertEquals(listOf("7"), repository.cachedEmails("INBOX").map { it.id })
    }

    @Test
    fun aReadBegunButNotYetRunShowsTheRowRead() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource())

        repository.beginRead("42", "INBOX")

        assertEquals("read", repository.cachedEmails("INBOX").single().status)
    }

    @Test
    fun anAbandonedRemovalShowsTheRowAgain() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource())

        repository.abandon(repository.beginRemoval("42", "INBOX"))

        assertEquals(listOf("42"), repository.cachedEmails("INBOX").map { it.id })
    }

    /** A failed read clears its overlay, and the list showing it has to repaint to say so. */
    @Test
    fun aFailedReadTellsTheListToRepaint() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("down")))
        var repaints = 0
        repository.setOverlayListener { repaints++ }

        repository.markRead(repository.beginRead("42", "INBOX"))

        assertEquals(1, repaints)
        assertEquals("unread", repository.cachedEmails("INBOX").single().status)
    }

    /** A failed removal is the inbox's to restore (or to drop, if the account moved on); a cache
     *  repaint behind its back would override that decision. */
    @Test
    fun aFailedRemovalDoesNotAskTheListToRepaint() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("down")))
        var repaints = 0
        repository.setOverlayListener { repaints++ }

        repository.delete(repository.beginRemoval("42", "INBOX"))

        assertEquals(0, repaints)
    }

    /** A refresh that filtered before the delete landed, and writes after it, must not write the
     *  row back: the removal waits for a refresh write already under way. */
    @Test
    fun aConfirmedDeleteIsNotUndoneByARefreshWriteAlreadyUnderWay() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource(fetchOutcome = snapshot("42", "7")))
        val writing = java.util.concurrent.CountDownLatch(1)
        val resume = java.util.concurrent.CountDownLatch(1)
        dao.beforeUpsert = {
            dao.beforeUpsert = null
            writing.countDown()
            resume.await(5, java.util.concurrent.TimeUnit.SECONDS)
        }
        val refresh = Thread { repository.refreshFolder("INBOX") }.apply { start() }
        assertTrue(writing.await(5, java.util.concurrent.TimeUnit.SECONDS))

        val delete = Thread { repository.delete(repository.beginRemoval("42", "INBOX")) }.apply { start() }
        delete.join(500) // Without the shared lock the delete finishes here, ahead of the write.
        resume.countDown()
        refresh.join(5_000)
        delete.join(5_000)

        assertTrue("the deleted row was written back", !dao.rows.containsKey("INBOX" to "42"))
    }

    @Test
    fun markReadFailure_showsTheRowUnreadAgain() {
        val dao = FakeEmailDao()
        dao.put(row("42", "INBOX"))
        val repository = repository(dao, FakeMailSource(actionOutcome = MailOutcome.ServiceUnavailable("down")))

        repository.markRead("42", "INBOX")

        assertEquals("unread", repository.cachedEmails("INBOX").single().status)
    }
}
