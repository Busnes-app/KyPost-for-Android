package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.push.ReconnectExpectation

@RunWith(AndroidJUnit4::class)
class KeptContactKeyReplayTest {
    private lateinit var db: AppDatabase
    private lateinit var server: FakeContactServer
    private val context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val account = ReconnectExpectation(TEST_PAIRING.subscriberId, TEST_PAIRING.serverUrl)
    private val owner = object : ContactsOwnerStore {
        var value: ReconnectExpectation? = null
        override fun contactsOwner() = value
        override fun setContactsOwner(owner: ReconnectExpectation?) { value = owner }
    }

    private fun repository() = ContactSyncRepository(
        db, ContactSyncClient(callFactory = server), ContactCursorStore(context, db), owner,
    ) { TEST_PAIRING }

    @Before fun setUp() {
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        server = FakeContactServer()
        owner.value = ReconnectExpectation("previous-subscriber", TEST_PAIRING.serverUrl)
    }

    @After fun tearDown() = db.close()

    private suspend fun seed() {
        db.contactDao().upsertAll(listOf(ContactDto(
            uid = "kept", rev = 12, fn = "Alice", pgpKey = KEY,
            emails = listOf(ContactFieldDto(value = "alice@example.invalid")),
            groupIDs = listOf("previous-group"), photoRef = "previous-photo",
        ).toEntity()))
    }

    private suspend fun pendingFlag(): JsonPrimitive? = db.pendingContactChangeDao().getAllPending()
        .single().let { Json.parseToJsonElement(it.payloadJson).jsonObject["omitUnusableKey"] as? JsonPrimitive }

    @Test fun bringPersistsRelayValidationIntentAndOriginalKeyAcrossALostReply() = runBlocking {
        seed()
        val first = repository()
        assertEquals(ContactSyncOutcome.AwaitingAccountChoice, first.sync())
        assertTrue(server.requests.isEmpty())
        assertTrue(db.pendingContactChangeDao().getAllPending().isEmpty())

        assertTrue(first.bringKeptContacts(account))
        assertEquals(JsonPrimitive(true), pendingFlag())
        val held = db.contactDao().getByUid("kept")!!
        assertEquals(KEY, held.pgpKey)
        assertEquals("[]", held.groupIDsJson)
        assertNull(held.photoRef)
        assertFalse(first.bringKeptContacts(account))

        server.loseNextResponse = true
        assertTrue(first.sync() is ContactSyncOutcome.Retry)
        assertEquals(JsonPrimitive(true), pendingFlag())
        assertEquals(ContactSyncOutcome.Success, repository().sync())
        assertTrue(db.pendingContactChangeDao().getAllPending().isEmpty())
        assertEquals(2, server.pushes.size)
        server.pushes.forEach { push ->
            assertEquals(KEY, push.changes.single().pgpKey)
            assertTrue(push.changes.single().omitUnusableKey)
            assertEquals("kept", push.changes.single().uid)
        }
    }

    @Test fun anOrdinaryEditRetainsUnsentReplayIntentButAChangedKeyIsStrict() = runBlocking {
        seed()
        val repository = repository()
        assertTrue(repository.bringKeptContacts(account))
        repository.queueUpdate(db.contactDao().getByUid("kept")!!.toDto().copy(fn = "Edited Alice"), false)
        assertEquals(JsonPrimitive(true), pendingFlag())
        repository.queueUpdate(db.contactDao().getByUid("kept")!!.toDto().copy(pgpKey = "replacement-key"), false)
        assertTrue(pendingFlag() != JsonPrimitive(true))
    }

    @Test fun aStaleAnswerChangesNothingAndRemoveNeverQueuesAnImport() = runBlocking {
        seed()
        val repository = repository()
        assertFalse(repository.bringKeptContacts(ReconnectExpectation("other", TEST_PAIRING.serverUrl)))
        assertTrue(db.pendingContactChangeDao().getAllPending().isEmpty())
        assertEquals(KEY, db.contactDao().getByUid("kept")!!.pgpKey)
        assertTrue(repository.removeKeptContacts(account))
        assertTrue(db.contactDao().getAll().isEmpty())
        assertTrue(db.pendingContactChangeDao().getAllPending().isEmpty())
        assertTrue(server.requests.isEmpty())
    }

    @Test fun ordinaryWritesCannotAdoptReplayConsentFromAnIncomingDto() = runBlocking {
        owner.value = account
        val repository = repository()
        val incoming = Json.decodeFromString<ContactDto>(
            """{"fn":"Ordinary","pgpKey":"$KEY","omitUnusableKey":true}""",
        )
        val uid = repository.queueCreate(incoming)
        assertTrue(pendingFlag() != JsonPrimitive(true))
        repository.queueUpdate(incoming.copy(uid = uid), false)
        assertTrue(pendingFlag() != JsonPrimitive(true))
    }

    @Test fun anExplicitKeyConfirmationEndsReplayKeyOmission() = runBlocking {
        seed()
        val repository = repository()
        assertTrue(repository.bringKeptContacts(account))
        repository.queueUpdate(db.contactDao().getByUid("kept")!!.toDto(), false, verifiedInPerson = true)
        assertTrue(pendingFlag() != JsonPrimitive(true))
    }

    private companion object {
        // The client must transmit these bytes unchanged: only the relay decides usability.
        const val KEY = "opaque-held-public-key"
    }
}
