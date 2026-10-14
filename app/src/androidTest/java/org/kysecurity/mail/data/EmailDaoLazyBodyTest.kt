package org.kysecurity.mail.data

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** `updateBody` against real SQL; the JVM fake in `MailRepositoryTest` only mirrors it.
 *
 *  This is the write that turns the emails table from a mirror of the inbox window into a cache of
 *  the messages actually opened — the inbox is fetched with `bodies=0`, so rows arrive without one. */
@RunWith(AndroidJUnit4::class)
class EmailDaoLazyBodyTest {

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

    private fun row(id: String, folder: String, body: String? = null) = EmailEntity(
        messageId = id,
        folder = folder,
        sender = "sender@example.com",
        sentTo = "me@example.com",
        subject = "Subject $id",
        preview = "preview $id",
        body = body,
        sourceMode = "relay",
    )

    @Test
    fun itFillsInABodyFetchedOnOpen() {
        dao.upsertAll(listOf(row("42", "INBOX")))

        dao.updateBody("42", "INBOX", "<p>hi</p>", "html")

        val filled = dao.getById("42", "INBOX")!!
        assertEquals("<p>hi</p>", filled.body)
        assertEquals("html", filled.bodyMode)
    }

    /** The metadata came from the inbox window and is fresher than anything the body fetch knows;
     *  an `@Upsert` of a whole row built around the body would roll it back. */
    @Test
    fun itLeavesEveryOtherColumnAlone() {
        dao.upsertAll(listOf(row("42", "INBOX").copy(status = "read", hasAttachments = true)))

        dao.updateBody("42", "INBOX", "<p>hi</p>", "html")

        val filled = dao.getById("42", "INBOX")!!
        assertEquals("Subject 42", filled.subject)
        assertEquals("preview 42", filled.preview)
        assertEquals("me@example.com", filled.sentTo)
        assertEquals("read", filled.status)
        assertEquals(true, filled.hasAttachments)
    }

    /** The table is keyed by folder AND messageId, because an IMAP UID is unique only within one
     *  mailbox. A body fetched from Archive must not land on the INBOX row that shares its id. */
    @Test
    fun itWritesOnlyToTheRequestedFolder() {
        dao.upsertAll(listOf(row("42", "INBOX"), row("42", "Archive")))

        dao.updateBody("42", "Archive", "archive body", "plain")

        assertEquals("archive body", dao.getById("42", "Archive")!!.body)
        assertNull(dao.getById("42", "INBOX")!!.body)
    }

    /** A message deleted from another client between the list load and the open. The write finds
     *  no row and must be a no-op, not an insert of a body with no metadata around it. */
    @Test
    fun aBodyForARowThatIsGoneInsertsNothing() {
        dao.updateBody("42", "INBOX", "<p>hi</p>", "html")

        assertNull(dao.getById("42", "INBOX"))
    }

    /** The list reads no bodies: one opened message can be megabytes, more than a cursor window. */
    @Test
    fun theFolderListReadsNoBody() {
        dao.upsertAll(
            listOf(
                row("42", "INBOX", body = "x".repeat(3 * 1024 * 1024)),
                row("43", "INBOX", body = " \n\t"),
                row("44", "INBOX"),
            ),
        )

        val rows = dao.getByFolder("INBOX").associate { it.messageId to it.hasBody }
        assertEquals(mapOf("42" to true, "43" to false, "44" to false), rows)
    }
}
