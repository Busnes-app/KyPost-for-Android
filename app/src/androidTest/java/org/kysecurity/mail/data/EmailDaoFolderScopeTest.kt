package org.kysecurity.mail.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The (folder, messageId) key against real SQL. The relay's id is an IMAP UID, unique only inside
 *  one mailbox, so INBOX and Archive can both hold `42`; the JVM fake mirrors this key, but only a
 *  real Room database proves the schema and the DAO's `WHERE` clauses agree with it. */
@RunWith(AndroidJUnit4::class)
class EmailDaoFolderScopeTest {

    private lateinit var db: AppDatabase
    private lateinit var dao: EmailDao

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(
            InstrumentationRegistry.getInstrumentation().targetContext,
            AppDatabase::class.java,
        ).allowMainThreadQueries().build()
        dao = db.emailDao()
    }

    @After
    fun tearDown() = db.close()

    private fun row(id: String, folder: String, body: String?, status: String = "unread") = EmailEntity(
        messageId = id,
        folder = folder,
        sender = "sender@example.com",
        subject = "Subject $folder/$id",
        preview = body.orEmpty(),
        body = body,
        status = status,
        sourceMode = "relay",
    )

    @Test
    fun theSameUidInTwoFoldersIsTwoRows() {
        dao.upsertAll(listOf(row("42", "INBOX", "the inbox one"), row("42", "Archive", "the archived one")))

        assertEquals("the inbox one", dao.getById("42", "INBOX")?.body)
        assertEquals("the archived one", dao.getById("42", "Archive")?.body)
        assertEquals(1, dao.getByFolder("INBOX").size)
        assertEquals(1, dao.getByFolder("Archive").size)
    }

    @Test
    fun upsertingOneFolderDoesNotRelocateTheOther() {
        dao.upsertAll(listOf(row("42", "Archive", "the archived one")))

        dao.replaceFolderSnapshot("INBOX", listOf(row("42", "INBOX", "the inbox one")))

        assertEquals("the archived one", dao.getById("42", "Archive")?.body)
        assertEquals("the inbox one", dao.getById("42", "INBOX")?.body)
    }

    @Test
    fun deleteIsScopedToItsFolder() {
        dao.upsertAll(listOf(row("42", "INBOX", "a"), row("42", "Archive", "b")))

        dao.deleteById("42", "INBOX")

        assertNull(dao.getById("42", "INBOX"))
        assertNotNull(dao.getById("42", "Archive"))
    }

    @Test
    fun statusUpdateIsScopedToItsFolder() {
        dao.upsertAll(listOf(row("42", "INBOX", "a"), row("42", "Archive", "b")))

        dao.updateStatus("42", "INBOX", "read")

        assertEquals("read", dao.getById("42", "INBOX")?.status)
        assertEquals("unread", dao.getById("42", "Archive")?.status)
    }

    @Test
    fun pruningOneFolderLeavesTheSameUidElsewhereAlone() {
        dao.upsertAll(listOf(row("42", "INBOX", "a"), row("42", "Archive", "b")))

        dao.replaceFolderSnapshot("INBOX", emptyList())

        assertNull(dao.getById("42", "INBOX"))
        assertNotNull(dao.getById("42", "Archive"))
    }

    @Test
    fun deltaAppliesUpsertsRemovalsAndPruneInOneTransaction() {
        dao.upsertAll(listOf(row("42", "Archive", "keep me"), row("7", "INBOX", "removed"), row("9", "INBOX", "stale")))

        dao.applyFolderDelta(
            folder = "INBOX",
            upserts = listOf(row("1", "INBOX", "new")),
            removedIds = listOf("7"),
            pruneKeepIds = listOf("1"),
            agedOutIds = emptyList(),
        )

        assertEquals(listOf("1"), dao.getByFolder("INBOX").map { it.messageId })
        assertNotNull("another folder's same-id row is untouched", dao.getById("42", "Archive"))
    }

    @Test
    fun partialDeltaDoesNotPrune() {
        dao.upsertAll(listOf(row("9", "INBOX", "unchanged, omitted from the delta")))

        dao.applyFolderDelta(
            folder = "INBOX",
            upserts = listOf(row("1", "INBOX", "new")),
            removedIds = emptyList(),
            pruneKeepIds = null,
            agedOutIds = emptyList(),
        )

        assertEquals(setOf("1", "9"), dao.getByFolder("INBOX").map { it.messageId }.toSet())
    }

    /** A snapshot lists only the window. Rows below it, aged out or paged in, are not its to prune. */
    @Test
    fun snapshotPrunesOnlyWindowRowsAndAgedOutRowsLeaveTheWindow() {
        dao.upsertAll(listOf(row("5", "INBOX", null), row("4", "INBOX", null), row("1", "INBOX", null).copy(inWindow = false)))

        dao.applyFolderDelta(
            folder = "INBOX",
            upserts = listOf(row("6", "INBOX", null)),
            removedIds = emptyList(),
            pruneKeepIds = null,
            agedOutIds = listOf("4"),
        )
        dao.replaceFolderSnapshot("INBOX", listOf(row("6", "INBOX", null)))

        assertEquals(setOf("6", "4", "1"), dao.getByFolder("INBOX").map { it.messageId }.toSet())
        assertEquals(false, dao.getById("4", "INBOX")?.inWindow)
        assertEquals(setOf("6", "4", "1"), dao.getIds("INBOX").toSet())
    }

    /** Only absent rows dated before the snapshot's oldest leave the window; an undated row and a
     *  row the snapshot lists stay in it, and another folder is untouched. */
    @Test
    fun markAgedOutBeforeComparesRelayTimestampsAndSkipsListedRows() {
        dao.upsertAll(
            listOf(
                row("old", "INBOX", null).copy(atUtc = "2026-01-01T00:00:00Z"),
                row("listed", "INBOX", null).copy(atUtc = "2025-01-01T00:00:00Z"),
                row("newer", "INBOX", null).copy(atUtc = "2026-06-01T00:00:00Z"),
                row("undated", "INBOX", null),
                row("old", "Archive", null).copy(atUtc = "2026-01-01T00:00:00Z"),
            ),
        )

        dao.markAgedOutBefore("INBOX", "2026-05-01T00:00:00Z", listOf("listed"))

        assertEquals(false, dao.getById("old", "INBOX")?.inWindow)
        assertEquals(true, dao.getById("listed", "INBOX")?.inWindow)
        assertEquals(true, dao.getById("newer", "INBOX")?.inWindow)
        assertEquals(true, dao.getById("undated", "INBOX")?.inWindow)
        assertEquals(true, dao.getById("old", "Archive")?.inWindow)
    }
}
