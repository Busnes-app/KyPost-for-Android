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

/** A key recorded for a recipient stays in force for encryption when sync removes the contact
 *  that held it: the sender still compares discovery keys against it. */
@RunWith(AndroidJUnit4::class)
class RecipientPinRetentionTest {

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

    private val sent = mutableListOf<ClientEncryptedMessage>()
    private var vaultOpened = false

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

    @Test
    fun aRecipientOmittedFromAFullSnapshot_stillRefusesADifferentKey() = runBlocking {
        val recorded = armoredPublicKey("Recorded <alice@example.invalid>")
        // Recorded locally, then gone from the server, its tombstone collected.
        db.contactDao().upsertAll(
            listOf(
                ContactDto(
                    uid = "alice",
                    rev = 3,
                    fn = "Alice",
                    emails = listOf(ContactFieldDto(value = "alice@example.invalid")),
                    pgpKey = recorded,
                ).toEntity(),
            ),
        )
        cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        server.seed(*Array(12) { ContactDto(uid = "remote-$it", fn = "Remote $it") })
        server.gcHighWater = 10

        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertNull("the snapshot removed the contact", db.contactDao().getByUid("alice"))

        val outcome = sender(armoredPublicKey("Other <alice@example.invalid>"))
            .send(MailDraft(to = "alice@example.invalid", subject = "s", body = "b", mode = "plain"), sign = false)

        assertTrue("expected KeyChanged, got $outcome", outcome is ClientSendOutcome.KeyChanged)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    @Suppress("DEPRECATION")
    private fun armoredPublicKey(uid: String): String {
        val rsa = RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        }
        val now = Date()
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), now)
        val sub = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), now)
        val ring = PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            null,
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply { addSubKey(sub) }.generatePublicKeyRing()
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(ring.encoded) }
        return out.toString(Charsets.UTF_8.name())
    }
}
