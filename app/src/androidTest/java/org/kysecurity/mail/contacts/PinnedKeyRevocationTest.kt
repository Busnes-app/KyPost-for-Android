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
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
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
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

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
        private val SECRET: PGPSecretKeyRing by lazy { generator("Alice <alice@example.invalid>").generateSecretKeyRing() }
        val KEY_ID: Long get() = SECRET.publicKey.keyID
        val PUBLIC: String by lazy { armored(publicRing(SECRET).encoded) }

        /** The same ring with a key revocation made by its own primary key. */
        val REVOKED: String by lazy {
            val ring = publicRing(SECRET)
            val primary = ring.publicKey
            val privateKey = SECRET.secretKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(null))
            val generator = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.algorithm, HashAlgorithmTags.SHA256))
            generator.init(PGPSignature.KEY_REVOCATION, privateKey)
            val revoked = PGPPublicKey.addCertification(primary, generator.generateCertification(primary))
            armored(PGPPublicKeyRing.insertPublicKey(ring, revoked).encoded)
        }

        fun publicRing(secret: PGPSecretKeyRing): PGPPublicKeyRing =
            PGPPublicKeyRing(secret.publicKeys.asSequence().toList())

        @Suppress("DEPRECATION")
        fun generator(uid: String): PGPKeyRingGenerator {
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
