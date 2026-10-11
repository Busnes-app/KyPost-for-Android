package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.pgp.ClientEncryptedSender
import org.kysecurity.mail.pgp.ClientSendOutcome
import org.kysecurity.mail.pgp.OpenOutcome
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.RawSignature
import org.kysecurity.mail.pgp.ResolveResult
import org.kysecurity.mail.pgp.ResolvedRecipientKey
import org.kysecurity.mail.pgp.RoomLocalSignerKeys
import org.kysecurity.mail.pgp.VaultOpener
import org.kysecurity.mail.pgp.VaultRecordKind
import org.kysecurity.mail.pgp.isPrimaryRevoked
import org.kysecurity.mail.pgp.signatureStateFor
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The owner of a pinned key revokes it, and the revocation arrives on the synced copy of the same
 *  key. The pin must take on that revocation: no verified signature from it, and no send to it. */
@RunWith(AndroidJUnit4::class)
class PinnedKeyRevocationTest {

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
            pairingProvider = { TEST_PAIRING },
        )
    }

    @After
    fun tearDown() = db.close()

    private fun alice(uid: String = "", key: String) =
        ContactDto(uid = uid, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = key)

    /** Verified on this device through the QR flow's save, synced, then revoked by its owner. */
    private suspend fun pinThenSyncRevocation(): String {
        val uid = repository.queueCreate(alice(key = PUBLIC), verifiedInPerson = true)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        val signed = signatureStateFor(RawSignature.Checked(KEY_ID, verified = true), emptyList(), keys())
        assertEquals("precondition: the pin verifies before revocation", PgpSignatureState.VERIFIED_CONFIRMED, signed)

        server.seed(alice(uid = uid, key = REVOKED))
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        return uid
    }

    /** The revocation is kept by the sync that delivered it, not by a later lookup: the synced
     *  contact can be gone before anything reads the pin. */
    @Test
    fun theRevocationIsStoredOnThePinByTheSyncThatDeliveredIt() = runBlocking {
        val uid = pinThenSyncRevocation()

        val stored = db.recipientPinDao().forAddress(ALICE)
        assertTrue("the pin is revoked straight after the sync", stored.isNotEmpty() && stored.all { isPrimaryRevoked(it.publicKey) })

        server.forget(uid)
        server.gcHighWater = Long.MAX_VALUE
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertEquals(null, db.contactDao().getByUid(uid))

        val verdict = signatureStateFor(RawSignature.Checked(KEY_ID, verified = true), emptyList(), keys())
        assertNotEquals(PgpSignatureState.VERIFIED_CONFIRMED, verdict)
    }

    private suspend fun keys() = RoomLocalSignerKeys { db }.keysFor(ALICE)

    @Test
    fun aSyncedRevocationOfThePinnedKey_preventsAConfirmedVerdict() = runBlocking {
        pinThenSyncRevocation()

        val verdict = signatureStateFor(RawSignature.Checked(KEY_ID, verified = true), emptyList(), keys())

        assertNotEquals(PgpSignatureState.VERIFIED_CONFIRMED, verdict)
    }

    @Test
    fun aSyncedRevocationOfThePinnedKey_refusesTheSendBeforeTheVault() = runBlocking {
        pinThenSyncRevocation()
        val sent = mutableListOf<ClientEncryptedMessage>()
        var vaultOpened = false
        val sender = ClientEncryptedSender(
            opener = object : VaultOpener {
                override suspend fun open(): OpenOutcome = OpenOutcome.Failed("unused").also { vaultOpened = true }
                override fun sealedKind(): VaultRecordKind? = null
            },
            resolver = { addresses ->
                ResolveResult.Success(addresses.map { ResolvedRecipientKey(it, REVOKED, "", "discovered", true) })
            },
            transport = { message -> sent += message; MailOutcome.Success(MailSendOutcome(true, "")) },
            localKeys = RoomLocalSignerKeys { db },
            accountAddress = "me@example.invalid",
        )

        val outcome = sender.send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

        assertEquals(ClientSendOutcome.RecipientKeyRevoked(listOf(ALICE)), outcome)
        assertEquals(false, vaultOpened)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
    }

    private companion object {
        const val ALICE = "alice@example.invalid"
        private val SECRET by lazy { RevocationTestKeys.secretRing("Alice <alice@example.invalid>") }
        val KEY_ID: Long get() = SECRET.publicKey.keyID
        val PUBLIC: String by lazy { RevocationTestKeys.public(SECRET) }

        /** The same ring with a key revocation made by its own primary key. */
        val REVOKED: String by lazy { RevocationTestKeys.primaryRevoked(SECRET, signer = SECRET) }
    }
}
