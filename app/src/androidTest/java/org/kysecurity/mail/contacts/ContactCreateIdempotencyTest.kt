package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.push.PairingData
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** A create carries its local uid, so neither a replayed push nor a later edit/delete queued
 *  before the first sync can produce a second server contact. */
@RunWith(AndroidJUnit4::class)
class ContactCreateIdempotencyTest {

    private lateinit var db: AppDatabase
    private lateinit var server: FakeContactServer
    private lateinit var repository: ContactSyncRepository

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        server = FakeContactServer()
        repository = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = server),
            cursorStore = ContactCursorStore(context, db),
            pairingProvider = { PAIRING },
        )
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun replayAfterTheReplyWasLost_leavesOneContact() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        server.loseNextResponse = true

        assertTrue(repository.sync() is ContactSyncOutcome.Retry)
        assertEquals("the outbox must survive a lost reply", 1, db.pendingContactChangeDao().getAllPending().size)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(listOf(uid), server.live().map { it.uid })
        assertEquals(listOf(uid), db.contactDao().observeAll().first().map { it.uid })
    }

    @Test
    fun createThenUpdateBeforeSync_leavesOneEditedContact() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        repository.queueUpdate(ContactDto(uid = uid, fn = "Janet"), identityChanged = false)

        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(listOf(uid to "Janet"), server.live().map { it.uid to it.fn })
        assertEquals(listOf(uid to "Janet"), db.contactDao().observeAll().first().map { it.uid to it.fn })
    }

    @Test
    fun createThenDeleteBeforeSync_leavesNothing() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        repository.queueDelete(uid, rev = 0)

        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(emptyList<ContactDto>(), server.live())
        assertEquals(0, db.contactDao().observeAll().first().size)
    }

    private companion object {
        val PAIRING = PairingData(
            subscriberId = "sub-1",
            serverUrl = "https://relay.example.com",
            registrationUrl = "https://relay.example.com/register",
            pairingToken = "token-1",
            deviceId = "device-1",
            deviceSecret = "secret-1",
            pairedAtEpochMs = 0L,
        )
    }
}
