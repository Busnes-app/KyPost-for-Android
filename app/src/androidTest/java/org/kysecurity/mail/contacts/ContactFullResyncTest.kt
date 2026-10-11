package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.ContactEntity
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** After tombstone GC the server can no longer say what it deleted, so the since=0 snapshot is
 *  the only truth: a local contact absent from it is gone, unless it is still waiting to be sent. */
@RunWith(AndroidJUnit4::class)
class ContactFullResyncTest {

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
        // A contact synced long ago whose tombstone the server has since collected.
        runBlocking {
            db.contactDao().upsertAll(listOf(ContactEntity(uid = "gone", rev = 3, fn = "Gone")))
            cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        }
        server.seed(*Array(12) { ContactDto(uid = "remote-$it", fn = "Remote $it") })
        server.gcHighWater = 10
    }

    @After
    fun tearDown() = db.close()

    private suspend fun localUids() = db.contactDao().observeAll().first().map { it.uid }.toSet()

    @Test
    fun tooOldPull_removesContactsTheSnapshotLacks() = runBlocking {
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(List(12) { "remote-$it" }.toSet(), localUids())
    }

    @Test
    fun tooOldPush_keepsCreatesStillWaitingToBeSent() = runBlocking {
        val refused = repository.queueCreate(ContactDto(fn = "Huge", notes = "x".repeat(1_100_000)))
        val sent = repository.queueCreate(ContactDto(fn = "Small"))

        repository.sync()

        assertEquals(List(12) { "remote-$it" }.toSet() + sent + refused, localUids())
    }
}
