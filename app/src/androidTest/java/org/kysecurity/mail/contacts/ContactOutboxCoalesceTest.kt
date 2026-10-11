package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.push.PairingData
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** One outbox row per uid, and coalescing never loses an edit a running sync already read. */
@RunWith(AndroidJUnit4::class)
class ContactOutboxCoalesceTest {

    private lateinit var db: AppDatabase
    private lateinit var server: FakeContactServer
    private lateinit var repository: ContactSyncRepository
    private val json = Json { ignoreUnknownKeys = true }

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

    private suspend fun pending() = db.pendingContactChangeDao().getAllPending()

    @Test
    fun updateAfterUnsyncedCreate_staysOneCreateWithTheNewPayload() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        repository.queueUpdate(ContactDto(uid = uid, fn = "Janet"), identityChanged = false)

        val rows = pending()
        assertEquals(1, rows.size)
        assertEquals(ContactSyncRepository.CHANGE_CREATE, rows[0].changeType)
        assertEquals("Janet", json.decodeFromString(ContactDto.serializer(), rows[0].payloadJson).fn)
    }

    @Test
    fun repeatedUpdates_keepOnlyTheLast() = runBlocking {
        repository.queueUpdate(ContactDto(uid = "u1", rev = 4, fn = "A"), identityChanged = false)
        repository.queueUpdate(ContactDto(uid = "u1", rev = 4, fn = "B"), identityChanged = false)

        val rows = pending()
        assertEquals(1, rows.size)
        assertEquals(ContactSyncRepository.CHANGE_UPDATE, rows[0].changeType)
        assertEquals("B", json.decodeFromString(ContactDto.serializer(), rows[0].payloadJson).fn)
    }

    @Test
    fun deleteAfterUnsyncedCreate_leavesOnlyTheDelete() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        repository.queueDelete(uid, rev = 0)

        assertEquals(listOf(uid to ContactSyncRepository.CHANGE_DELETE), pending().map { it.localUid to it.changeType })
    }

    @Test
    fun editDuringAnInFlightCreate_survivesTheAck() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        server.duringPush = {
            runBlocking { repository.queueUpdate(ContactDto(uid = uid, fn = "Janet"), identityChanged = false) }
        }

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(listOf(uid to "Janet"), server.live().map { it.uid to it.fn })
        assertEquals(0, pending().size)
    }

    @Test
    fun deleteDuringAnInFlightCreate_stillDeletesOnTheServer() = runBlocking {
        val uid = repository.queueCreate(ContactDto(fn = "Jane"))
        server.duringPush = { runBlocking { repository.queueDelete(uid, rev = 0) } }

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertEquals(emptyList<ContactDto>(), server.live())
        assertEquals(0, pending().size)
        assertEquals(null, db.contactDao().getByUid(uid))
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
