package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.PendingContactChangeEntity
import org.kysecurity.mail.push.PairingData
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.Callback
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import okio.Timeout
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The dangerous half of contact sync: what the outbox transaction does with a row it cannot
 *  encode, and what the `tooOld` branch does with rows the server has already committed. */
@RunWith(AndroidJUnit4::class)
class ContactSyncOutboxSafetyTest {

    private lateinit var db: AppDatabase
    private lateinit var factory: RecordingCallFactory
    private lateinit var repository: ContactSyncRepository

    private val pairing = PairingData(
        subscriberId = SUB,
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/register",
        pairingToken = "token-1",
        deviceId = "device-1",
        deviceSecret = "secret-1",
        pairedAtEpochMs = 0L,
    )

    @Before
    fun setUp() {
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        factory = RecordingCallFactory()
        repository = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = factory),
            cursorStore = ContactCursorStore(context, db),
            pairingProvider = { pairing },
        )
    }

    @After
    fun tearDown() = db.close()

    private suspend fun enqueue(type: String, payload: String) {
        db.pendingContactChangeDao().enqueue(
            PendingContactChangeEntity(
                localUid = "uid-1",
                rev = 3,
                changeType = type,
                payloadJson = payload,
                createdAtEpochMs = 1L,
            ),
        )
    }

    @Test
    fun malformedPayload_neverReachesTheNetworkAndKeepsTheOutbox() = runBlocking {
        enqueue(ContactSyncRepository.CHANGE_UPDATE, "{not json")

        val outcome = repository.sync()

        assertTrue("expected a visible failure, got $outcome", outcome is ContactSyncOutcome.Retry)
        assertEquals("nothing may be sent", 0, factory.requests.size)
        assertEquals("the only copy of the edit must survive", 1, db.pendingContactChangeDao().getAllPending().size)
    }

    @Test
    fun unknownChangeType_failsClosed() = runBlocking {
        enqueue("merge", """{"fn":"Jane"}""")

        val outcome = repository.sync()

        assertTrue("expected a visible failure, got $outcome", outcome is ContactSyncOutcome.Retry)
        assertEquals(0, factory.requests.size)
        assertEquals(1, db.pendingChangeCount())
    }

    @Test
    fun oneBadRowStopsTheWholeBatch_theGoodRowsAreNotSentEither() = runBlocking {
        enqueue(ContactSyncRepository.CHANGE_UPDATE, """{"uid":"uid-9","fn":"Valid"}""")
        enqueue(ContactSyncRepository.CHANGE_UPDATE, "{not json")

        repository.sync()

        assertEquals(0, factory.requests.size)
        assertEquals(2, db.pendingChangeCount())
    }

    /** Wire contract: the server commits pushed changes BEFORE computing tooOld, so the rows are
     *  acknowledged. Only the cursor is discarded, forcing a full since=0 re-pull. */
    @Test
    fun tooOld_clearsTheAcknowledgedOutboxAndResetsOnlyTheCursor() = runBlocking {
        val cursorStore = ContactCursorStore(
            InstrumentationRegistry.getInstrumentation().targetContext,
            db,
        )
        cursorStore.advanceCursor(SUB, 42L)
        enqueue(ContactSyncRepository.CHANGE_CREATE, """{"uid":"","fn":"Jane"}""")
        factory.body = """{"cursor":0,"tooOld":true,"changed":[],"deleted":[]}"""

        val outcome = repository.sync()

        assertTrue(outcome is ContactSyncOutcome.Success)
        assertEquals("the push must actually have gone out", 1, factory.requests.size)
        assertEquals("acknowledged rows must not be replayed", 0, db.pendingChangeCount())
        assertEquals("cursor must be discarded for a full re-pull", 0L, cursorStore.cursor(SUB))
    }

    @Test
    fun syncStatus_countsContactsNotRowsAndReportsTheFailure() = runBlocking {
        enqueue(ContactSyncRepository.CHANGE_UPDATE, "{not json")
        enqueue(ContactSyncRepository.CHANGE_UPDATE, "{not json")
        repeat(STUCK_AFTER_FAILURES) { repository.sync() }

        val status = repository.observeSyncStatus(now = { 2L }).first()

        assertTrue("expected stuck, got $status", status is ContactSyncStatus.Stuck)
        assertEquals("two rows for one contact are one waiting change", 1, (status as ContactSyncStatus.Stuck).pending)
        assertTrue(status.reason is ContactSyncOutcome.Retry)
    }

    @Test
    fun import_queuesEveryContactAsACreate() = runBlocking {
        val queued = repository.queueImport(listOf(ContactDto(fn = "A"), ContactDto(fn = "B")))

        assertTrue(queued)
        val pending = db.pendingContactChangeDao().getAllPending()
        assertEquals(listOf(ContactSyncRepository.CHANGE_CREATE, ContactSyncRepository.CHANGE_CREATE), pending.map { it.changeType })
        assertEquals(2, db.contactDao().observeAll().first().size)
    }

    @Test
    fun import_refusesANonEmptyOutboxAndAddsNothing() = runBlocking {
        enqueue(ContactSyncRepository.CHANGE_UPDATE, """{"uid":"uid-1","fn":"Edit"}""")

        val queued = repository.queueImport(listOf(ContactDto(fn = "A")))

        assertTrue(!queued)
        assertEquals(1, db.pendingChangeCount())
        assertEquals(0, db.contactDao().observeAll().first().size)
    }

    /** Recorded after unlock, a waiting caller could finish and record first, so an old failure
     *  overwrote a newer success. The Unconfined collector runs inline at each record. */
    @Test
    fun syncOutcome_isRecordedWhileTheSyncLockIsHeld() = runBlocking {
        enqueue(ContactSyncRepository.CHANGE_UPDATE, "{not json")
        val lockedAtRecord = mutableListOf<Boolean>()
        val watcher = launch(Dispatchers.Unconfined) {
            repository.health.failures.drop(1).collect { lockedAtRecord += repository.syncMutex.isLocked }
        }

        repository.sync()
        watcher.cancel()

        assertEquals(listOf(true), lockedAtRecord)
    }

    private suspend fun AppDatabase.pendingChangeCount() = pendingContactChangeDao().getAllPending().size

    private companion object {
        const val SUB = "sub-1"
    }
}

private class RecordingCallFactory : Call.Factory {
    val requests = mutableListOf<Request>()
    var body: String = """{"cursor":1,"tooOld":false,"changed":[],"deleted":[]}"""

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(
            request,
            Response.Builder()
                .request(request)
                .protocol(Protocol.HTTP_1_1)
                .code(200)
                .message("OK")
                .body(body.toResponseBody("application/json".toMediaType()))
                .build(),
        )
    }
}

private class FakeCall(private val req: Request, private val response: Response) : Call {
    private var executed = false
    private var canceled = false
    override fun request(): Request = req
    override fun execute(): Response {
        executed = true
        return response
    }
    override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(this, response)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = canceled
    override fun timeout(): Timeout = Timeout.NONE
    override fun clone(): Call = FakeCall(req, response)
}
