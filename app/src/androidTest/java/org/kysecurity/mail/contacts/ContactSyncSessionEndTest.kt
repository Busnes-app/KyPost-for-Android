package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.ProcessState
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

/** An unpair advances the session while a sync reply is in flight; the reply must write nothing,
 *  or the purged account's contacts come back for whoever pairs next. */
@RunWith(AndroidJUnit4::class)
class ContactSyncSessionEndTest {

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
            pairingProvider = {
                PairingData(
                    subscriberId = "sub-1",
                    serverUrl = "https://relay.example.com",
                    registrationUrl = "https://relay.example.com/register",
                    pairingToken = "token-1",
                    deviceId = "device-1",
                    deviceSecret = "secret-1",
                    pairedAtEpochMs = 0L,
                )
            },
        )
    }

    @After
    fun tearDown() = db.close()

    @Test
    fun aReplyArrivingAfterTheSessionEndedWritesNothing() = runBlocking {
        server.seed(ContactDto(uid = "remote-1", fn = "Remote"))
        repository.queueCreate(ContactDto(fn = "Local"))
        server.duringPush = { ProcessState.advanceGeneration() }

        assertEquals(ContactSyncOutcome.NotPaired, repository.sync())

        val names = db.contactDao().observeAll().first().map { it.fn }
        assertTrue("the stale reply wrote $names", "Remote" !in names)
        assertEquals("the stale reply must not ack the outbox", 1, db.pendingContactChangeDao().getAllPending().size)
    }
}
