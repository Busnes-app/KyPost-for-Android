package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
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
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
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
import org.kysecurity.mail.pgp.PgpSignatureState
import org.kysecurity.mail.pgp.RawSignature
import org.kysecurity.mail.pgp.signatureStateFor
import org.kysecurity.mail.pgp.PgpFingerprint
import org.kysecurity.mail.pgp.ResolveResult
import org.kysecurity.mail.pgp.ResolvedRecipientKey
import org.kysecurity.mail.pgp.RoomLocalSignerKeys
import org.kysecurity.mail.pgp.VaultOpener
import org.kysecurity.mail.pgp.VaultRecordKind
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

/** A key the app trusted before recipient pins existed is still trusted after the upgrade: a
 *  snapshot that drops the contact must not open the door to a relay-supplied key. */
@RunWith(AndroidJUnit4::class)
class LegacyKeyMigrationTest {
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext

    @get:Rule
    val helper = MigrationTestHelper(instrumentation, AppDatabase::class.java.canonicalName, FrameworkSQLiteOpenHelperFactory())

    private var db: AppDatabase? = null

    @After
    fun tearDown() {
        db?.close()
        context.deleteDatabase(TEST_DB)
    }

    /** A v12 database whose only contact holds [KEY_A], upgraded to the current schema. */
    private fun upgradedV12(): AppDatabase {
        helper.createDatabase(TEST_DB, 12).apply {
            execSQL(
                "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson, pgpKey, pgpKeyFingerprint) " +
                    "VALUES ('alice', 3, 'Alice', ?, '[]', '[]', ?, ?)",
                arrayOf("""[{"value":"Alice@Example.invalid"}]""", KEY_A, PgpFingerprint.compute(KEY_A)),
            )
            close()
        }
        return Room.databaseBuilder(context, AppDatabase::class.java, TEST_DB)
            .addMigrations(AppDatabase.MIGRATION_12_13, AppDatabase.MIGRATION_13_14)
            .build()
            .also { db = it }
    }

    private fun sender(database: AppDatabase, discovered: String, sent: MutableList<ClientEncryptedMessage>, onVault: () -> Unit) =
        ClientEncryptedSender(
            opener = object : VaultOpener {
                override suspend fun open(): OpenOutcome = OpenOutcome.Failed("unused").also { onVault() }
                override fun sealedKind(): VaultRecordKind? = null
            },
            resolver = { addresses -> ResolveResult.Success(addresses.map { ResolvedRecipientKey(it, discovered, "", "discovered", true) }) },
            transport = { message -> sent += message; MailOutcome.Success(MailSendOutcome(true, "")) },
            localKeys = RoomLocalSignerKeys { database },
            accountAddress = "me@example.invalid",
        )

    @Test
    fun aV12ContactsKey_survivesTheUpgradeAndASnapshotThatDropsTheContact() = runBlocking {
        val database = upgradedV12()

        val server = FakeContactServer().apply { gcHighWater = Long.MAX_VALUE }
        val cursorStore = ContactCursorStore(context, database)
        cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        val repository = ContactSyncRepository(database, ContactSyncClient(callFactory = server), cursorStore) { TEST_PAIRING }
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertNull("the snapshot removed the contact", database.contactDao().getByUid("alice"))

        val sent = mutableListOf<ClientEncryptedMessage>()
        var vaultOpened = false
        val outcome = sender(database, KEY_B, sent) { vaultOpened = true }
            .send(MailDraft(to = "alice@example.invalid", subject = "s", body = "b", mode = "plain"), sign = false)

        assertTrue("expected KeyChanged, got $outcome", outcome is ClientSendOutcome.KeyChanged)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    /** A pin seeded by the migration takes a synced revocation of its own key exactly as a pin
     *  verified by QR does: no confirmed verdict, and the send stops before the vault. */
    @Test
    fun aBackfilledPin_takesASyncedRevocationOfItsKey() = runBlocking {
        val database = upgradedV12()
        suspend fun verdict() = signatureStateFor(
            RawSignature.Checked(SECRET_A.publicKey.keyID, verified = true),
            emptyList(),
            RoomLocalSignerKeys { database }.keysFor("alice@example.invalid"),
        )
        assertEquals("precondition: the backfilled pin verifies", PgpSignatureState.VERIFIED_CONFIRMED, verdict())

        val server = FakeContactServer()
        server.seed(
            ContactDto(uid = "alice", fn = "Alice", emails = listOf(ContactFieldDto(value = "Alice@Example.invalid")), pgpKey = REVOKED_A),
        )
        val repository = ContactSyncRepository(database, ContactSyncClient(callFactory = server), ContactCursorStore(context, database)) { TEST_PAIRING }
        assertTrue(repository.sync() is ContactSyncOutcome.Success)

        assertNotEquals(PgpSignatureState.VERIFIED_CONFIRMED, verdict())
        val sent = mutableListOf<ClientEncryptedMessage>()
        var vaultOpened = false
        val outcome = sender(database, REVOKED_A, sent) { vaultOpened = true }
            .send(MailDraft(to = "alice@example.invalid", subject = "s", body = "b", mode = "plain"), sign = false)
        // By name: the outcome type arrives with the revocation work.
        assertEquals("got $outcome", "RecipientKeyRevoked", outcome::class.simpleName)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    private companion object {
        const val TEST_DB = "legacy-key-migration-test"
        val SECRET_A: PGPSecretKeyRing by lazy { secretRing("A <alice@example.invalid>") }
        val KEY_A: String by lazy { armored(publicRing(SECRET_A).encoded) }
        val KEY_B: String by lazy { armored(publicRing(secretRing("B <alice@example.invalid>")).encoded) }

        /** [KEY_A] with a key revocation made by its own primary key. */
        val REVOKED_A: String by lazy {
            val ring = publicRing(SECRET_A)
            val primary = ring.publicKey
            val privateKey = SECRET_A.secretKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(null))
            val generator = PGPSignatureGenerator(BcPGPContentSignerBuilder(primary.algorithm, HashAlgorithmTags.SHA256))
            generator.init(PGPSignature.KEY_REVOCATION, privateKey)
            val revoked = PGPPublicKey.addCertification(primary, generator.generateCertification(primary))
            armored(PGPPublicKeyRing.insertPublicKey(ring, revoked).encoded)
        }

        fun publicRing(secret: PGPSecretKeyRing) = PGPPublicKeyRing(secret.publicKeys.asSequence().toList())

        fun armored(bytes: ByteArray): String {
            val out = ByteArrayOutputStream()
            ArmoredOutputStream(out).use { it.write(bytes) }
            return out.toString(Charsets.UTF_8.name())
        }

        @Suppress("DEPRECATION")
        fun secretRing(uid: String): PGPSecretKeyRing {
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
            ).apply { addSubKey(sub) }.generateSecretKeyRing()
            return ring
        }
    }
}
