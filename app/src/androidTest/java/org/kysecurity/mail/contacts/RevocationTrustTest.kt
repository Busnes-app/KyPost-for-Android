package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.RevocationTestKeys.primaryRevoked
import org.kysecurity.mail.contacts.RevocationTestKeys.public
import org.kysecurity.mail.contacts.RevocationTestKeys.ring
import org.kysecurity.mail.contacts.RevocationTestKeys.secretRing
import org.kysecurity.mail.contacts.RevocationTestKeys.subkeyRevoked
import org.kysecurity.mail.contacts.RevocationTestKeys.subkeys
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.data.RecipientPinEntity
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.pgp.ClientEncryptedSender
import org.kysecurity.mail.pgp.ClientSendOutcome
import org.kysecurity.mail.pgp.OpenOutcome
import org.kysecurity.mail.pgp.PgpFingerprint
import org.kysecurity.mail.pgp.ResolveResult
import org.kysecurity.mail.pgp.ResolvedRecipientKey
import org.kysecurity.mail.pgp.RoomLocalSignerKeys
import org.kysecurity.mail.pgp.VaultOpener
import org.kysecurity.mail.pgp.VaultRecordKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** A revocation counts only when it verifies against the key it revokes, and "the key you verified
 *  has been revoked" is said only about a key the user verified. */
@RunWith(AndroidJUnit4::class)
class RevocationTrustTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private lateinit var db: AppDatabase

    @Before
    fun setUp() {
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
    }

    @After
    fun tearDown() = db.close()

    private suspend fun pin(key: String) = db.recipientPinDao().upsertAll(
        listOf(RecipientPinEntity(ALICE, PgpFingerprint.compute(key).orEmpty(), key, confirmed = true)),
    )

    private suspend fun syncedContact(key: String) = db.contactDao().upsertAll(
        listOf(ContactDto(uid = "alice", rev = 1, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = key).toEntity()),
    )

    private suspend fun send(discovered: String): ClientSendOutcome = ClientEncryptedSender(
        opener = object : VaultOpener {
            override suspend fun open(): OpenOutcome = OpenOutcome.Failed("unused")
            override fun sealedKind(): VaultRecordKind? = null
        },
        resolver = { addresses -> ResolveResult.Success(addresses.map { ResolvedRecipientKey(it, discovered, "", "discovered", true) }) },
        transport = { MailOutcome.Success(MailSendOutcome(true, "")) },
        localKeys = RoomLocalSignerKeys { db },
        accountAddress = "me@example.invalid",
    ).send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

    @Test
    fun anUnpinnedKeyWithAForgedRevocation_isNotAVerifiedKeyRevoked() = runBlocking {
        syncedContact(primaryRevoked(A, signer = B))

        val outcome = send(public(A))

        assertFalse("got $outcome", outcome is ClientSendOutcome.RecipientKeyRevoked)
    }

    @Test
    fun aPinWithAForgedRevocation_isNotRevoked() = runBlocking {
        pin(primaryRevoked(A, signer = B))

        val outcome = send(public(A))

        assertFalse("got $outcome", outcome is ClientSendOutcome.RecipientKeyRevoked)
    }

    @Test
    fun aPinWithItsOwnersRevocation_isRevoked() = runBlocking {
        pin(primaryRevoked(A, signer = A))

        assertEquals(ClientSendOutcome.RecipientKeyRevoked(listOf(ALICE)), send(public(A)))
    }

    /** A subkey revocation reaching a pinned recipient through sync is stored on the pin; a forged
     *  one is not. Nothing else crosses from the synced copy. */
    @Test
    fun aSyncedSubkeyRevocation_isStoredOnThePin_aForgedOneIsNot() = runBlocking {
        val server = FakeContactServer()
        val repository = ContactSyncRepository(db, ContactSyncClient(callFactory = server), ContactCursorStore(context, db)) { TEST_PAIRING }
        val uid = repository.queueCreate(
            ContactDto(fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = public(C)),
            verifiedInPerson = true,
        )
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        val (older, newest) = subkeys(C).map { it.keyID }

        fun storedSubkeysRevoked() = runBlocking {
            ring(db.recipientPinDao().forAddress(ALICE).single().publicKey).publicKeys.asSequence()
                .filter { !it.isMasterKey }.associate { it.keyID to it.hasRevocation() }
        }

        server.seed(ContactDto(uid = uid, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = subkeyRevoked(C, 0, signer = B)))
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertEquals("a forged subkey revocation is ignored", mapOf(older to false, newest to false), storedSubkeysRevoked())

        server.seed(ContactDto(uid = uid, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = subkeyRevoked(C, 1, signer = C)))
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertEquals("the owner's subkey revocation is stored", mapOf(older to false, newest to true), storedSubkeysRevoked())
        val stored = db.recipientPinDao().forAddress(ALICE).single().publicKey
        assertNotEquals("the primary is not revoked", true, ring(stored).publicKey.hasRevocation())
        assertEquals(PgpFingerprint.compute(public(C)), PgpFingerprint.compute(stored))
    }

    /** A revoked copy of the pinned key saved on this device, before any sync, revokes the stored
     *  pin when it is saved: lookups only read pins. */
    @Test
    fun aLocallySavedRevocation_isStoredOnThePinAtOnce() = runBlocking {
        val repository = ContactSyncRepository(db, ContactSyncClient(callFactory = FakeContactServer()), ContactCursorStore(context, db)) { TEST_PAIRING }
        val uid = repository.queueCreate(
            ContactDto(fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = public(A)),
            verifiedInPerson = true,
        )

        repository.queueUpdate(
            ContactDto(uid = uid, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = primaryRevoked(A, signer = A)),
            identityChanged = false,
        )

        assertTrue(ring(db.recipientPinDao().forAddress(ALICE).single().publicKey).publicKey.hasRevocation())
    }

    private companion object {
        const val ALICE = "alice@example.invalid"
        val A by lazy { secretRing("A <alice@example.invalid>") }
        val B by lazy { secretRing("B <b@example.invalid>") }
        val C by lazy { secretRing("C <alice@example.invalid>", subkeys = 2) }
    }
}
