package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** An outbox larger than one server request drains in batches instead of retrying forever. */
@RunWith(AndroidJUnit4::class)
class ContactPushBatchingTest {

    private lateinit var db: AppDatabase
    private lateinit var server: FakeContactServer
    private lateinit var cursorStore: ContactCursorStore
    private lateinit var repository: ContactSyncRepository

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        server = FakeContactServer()
        cursorStore = ContactCursorStore(context, db)
        repository = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = server),
            cursorStore = cursorStore,
            pairingProvider = { TEST_PAIRING },
        )
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun twelveHundredChanges_goOutInThreeRequests() = runBlocking {
        repeat(1200) { repository.queueCreate(ContactDto(fn = "Contact $it")) }

        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(listOf("POST", "POST", "POST"), server.requests)
        assertEquals(1200, server.live().size)
        assertEquals(0, db.pendingContactChangeDao().getAllPending().size)
    }

    /** A sync that saw tooOld and then failed must still end, on a later sync, with the snapshot:
     *  its reset cursor is the only trace that one is owed. */
    @Test
    fun aFailedBatchAfterTooOld_stillGetsTheSnapshotOnRetry() = runBlocking {
        db.contactDao().upsertAll(listOf(ContactDto(uid = "forgotten", rev = 2, fn = "Forgotten").toEntity()))
        server.gcHighWater = 10
        server.failPost = 2
        cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        repeat(600) { repository.queueCreate(ContactDto(fn = "Contact $it")) }

        assertTrue(repository.sync() is ContactSyncOutcome.Retry)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(0, db.pendingContactChangeDao().getAllPending().size)
        assertEquals("the snapshot removes what the server no longer has", null, db.contactDao().getByUid("forgotten"))
        assertEquals(600, db.contactDao().observeAll().first().size)
    }

    @Test
    fun tooOldMidPush_clearsTheOutboxAndEndsWithOneFullPull() = runBlocking {
        server.seed(*Array(12) { ContactDto(uid = "remote-$it", fn = "Remote $it") })
        server.gcHighWater = 10
        cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        repeat(600) { repository.queueCreate(ContactDto(fn = "Contact $it")) }

        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(listOf("POST", "POST", "GET since=0"), server.requests)
        assertEquals(0, db.pendingContactChangeDao().getAllPending().size)
        assertEquals(612, db.contactDao().observeAll().first().size)
        assertEquals(612L, cursorStore.cursor(TEST_PAIRING.subscriberId))
    }

    @Test
    fun aChangeTooLargeForAnyRequest_staysQueuedAndTheRestGoOut() = runBlocking {
        val huge = repository.queueCreate(ContactDto(fn = "Huge", notes = "x".repeat(1_100_000)))
        repository.queueCreate(ContactDto(fn = "Small 1"))
        repository.queueCreate(ContactDto(fn = "Small 2"))

        val outcome = repository.sync()

        assertTrue("got $outcome", outcome is ContactSyncOutcome.Retry)
        assertEquals(setOf("Small 1", "Small 2"), server.live().map { it.fn }.toSet())
        assertEquals(listOf(huge), db.pendingContactChangeDao().getAllPending().map { it.localUid })
    }
}
