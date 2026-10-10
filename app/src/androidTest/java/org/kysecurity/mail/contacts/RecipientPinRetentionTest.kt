package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import org.kysecurity.mail.pgp.ClientEncryptedSender
import org.kysecurity.mail.pgp.ClientSendOutcome
import org.kysecurity.mail.pgp.EnrollmentSession
import org.kysecurity.mail.pgp.OpenOutcome
import org.kysecurity.mail.pgp.ResolveResult
import org.kysecurity.mail.pgp.ResolvedRecipientKey
import org.kysecurity.mail.pgp.RoomLocalSignerKeys
import org.kysecurity.mail.pgp.VaultOpener
import org.kysecurity.mail.pgp.VaultRecordKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

/** A key verified on this device decides which key a recipient may be sent to. Keys that arrive
 *  through sync, whether on a replacement contact or as an update, do not; only re-verifying
 *  on this device replaces the pin. */
@RunWith(AndroidJUnit4::class)
class RecipientPinRetentionTest {

    private lateinit var db: AppDatabase
    private lateinit var server: FakeContactServer
    private lateinit var repository: ContactSyncRepository

    private val sent = mutableListOf<ClientEncryptedMessage>()
    private var vaultOpened = false

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
    fun tearDown() {
        EnrollmentSession.clear()
        db.close()
    }

    private fun sender(discoveryKey: String) = ClientEncryptedSender(
        opener = object : VaultOpener {
            override suspend fun open(): OpenOutcome = OpenOutcome.Failed("unused").also { vaultOpened = true }
            override fun sealedKind(): VaultRecordKind? = null
        },
        resolver = { addresses ->
            ResolveResult.Success(addresses.map { ResolvedRecipientKey(it, discoveryKey, "", "discovered", true) })
        },
        transport = { message -> sent += message; MailOutcome.Success(MailSendOutcome(true, "")) },
        localKeys = RoomLocalSignerKeys { db },
        accountAddress = "me@example.invalid",
    )

    private suspend fun sendTo(discoveryKey: String) = sender(discoveryKey)
        .send(MailDraft(to = ALICE, subject = "s", body = "b", mode = "plain"), sign = false)

    private fun alice(uid: String = "", key: String) =
        ContactDto(uid = uid, fn = "Alice", emails = listOf(ContactFieldDto(value = ALICE)), pgpKey = key)

    /** The QR flow's save: the user compared this key's fingerprint on screen. Then synced. */
    private suspend fun verifyOnThisDevice(key: String): String {
        val uid = repository.queueCreate(alice(key = key), verifiedInPerson = true)
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        return uid
    }

    private fun assertRefusedUnsent(outcome: ClientSendOutcome) {
        assertTrue("expected KeyChanged, got $outcome", outcome is ClientSendOutcome.KeyChanged)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    @Test
    fun aVerifiedRecipientOmittedFromAFullSnapshot_stillRefusesADifferentKey() = runBlocking {
        val uid = verifyOnThisDevice(KEY_A)
        server.forget(uid)
        server.gcHighWater = Long.MAX_VALUE

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertNull("the snapshot removed the contact", db.contactDao().getByUid(uid))

        assertRefusedUnsent(sendTo(KEY_B))
    }

    @Test
    fun aSnapshotReplacementContactWithADifferentKey_isRefused() = runBlocking {
        val uid = verifyOnThisDevice(KEY_A)
        server.forget(uid)
        server.seed(alice(uid = "alice-replacement", key = KEY_B))
        server.gcHighWater = Long.MAX_VALUE

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertEquals(KEY_B, db.contactDao().getByUid("alice-replacement")?.pgpKey)

        assertRefusedUnsent(sendTo(KEY_B))
    }

    @Test
    fun aServerUpdateGivingAVerifiedContactADifferentKey_isRefused() = runBlocking {
        val uid = verifyOnThisDevice(KEY_A)
        server.seed(alice(uid = uid, key = KEY_B))

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertEquals(KEY_B, db.contactDao().getByUid(uid)?.pgpKey)

        assertRefusedUnsent(sendTo(KEY_B))
    }

    @Test
    fun reVerifyingOnThisDevice_replacesThePin_andTheNextSendGoesOut() = runBlocking {
        val uid = verifyOnThisDevice(KEY_A)
        server.seed(alice(uid = uid, key = KEY_B))
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertRefusedUnsent(sendTo(KEY_B))

        // The QR flow's save onto the existing contact, after comparing the new fingerprint.
        val contact = db.contactDao().getByUid(uid)!!.toDto()
        repository.queueUpdate(contact.copy(pgpKey = KEY_B), identityChanged = false, verifiedInPerson = true)
        EnrollmentSession.put(OWN_SECRET_KEY.toCharArray())

        val outcome = sendTo(KEY_B)

        assertTrue("expected Sent, got $outcome", outcome is ClientSendOutcome.Sent)
        assertEquals(1, sent.size)
    }

    private companion object {
        const val ALICE = "alice@example.invalid"
        val KEY_A: String by lazy { armored(ring("A <alice@example.invalid>").generatePublicKeyRing().encoded) }
        val KEY_B: String by lazy { armored(ring("B <alice@example.invalid>").generatePublicKeyRing().encoded) }
        val OWN_SECRET_KEY: String by lazy { armored(ring("Me <me@example.invalid>").generateSecretKeyRing().encoded) }

        @Suppress("DEPRECATION")
        fun ring(uid: String): PGPKeyRingGenerator {
            val rsa = RSAKeyPairGenerator().apply {
                init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
            }
            val now = Date()
            val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), now)
            val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), now)
            return PGPKeyRingGenerator(
                PGPSignature.POSITIVE_CERTIFICATION,
                primary,
                uid,
                BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
                null,
                null,
                BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
                null,
            ).apply { addSubKey(sub) }
        }

        fun armored(bytes: ByteArray): String {
            val out = ByteArrayOutputStream()
            ArmoredOutputStream(out).use { it.write(bytes) }
            return out.toString(Charsets.UTF_8.name())
        }
    }
}
