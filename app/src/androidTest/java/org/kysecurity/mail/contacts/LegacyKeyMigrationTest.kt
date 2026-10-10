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
import org.kysecurity.mail.pgp.PgpFingerprint
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

    @Test
    fun aV12ContactsKey_survivesTheUpgradeAndASnapshotThatDropsTheContact() = runBlocking {
        helper.createDatabase(TEST_DB, 12).apply {
            execSQL(
                "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson, pgpKey, pgpKeyFingerprint) " +
                    "VALUES ('alice', 3, 'Alice', ?, '[]', '[]', ?, ?)",
                arrayOf("""[{"value":"Alice@Example.invalid"}]""", KEY_A, PgpFingerprint.compute(KEY_A)),
            )
            close()
        }
        val database = Room.databaseBuilder(context, AppDatabase::class.java, TEST_DB)
            .addMigrations(AppDatabase.MIGRATION_12_13, AppDatabase.MIGRATION_13_14, AppDatabase.MIGRATION_14_15)
            .build()
            .also { db = it }

        val server = FakeContactServer().apply { gcHighWater = Long.MAX_VALUE }
        val cursorStore = ContactCursorStore(context, database)
        cursorStore.advanceCursor(TEST_PAIRING.subscriberId, 5)
        val repository = ContactSyncRepository(database, ContactSyncClient(callFactory = server), cursorStore) { TEST_PAIRING }
        assertTrue(repository.sync() is ContactSyncOutcome.Success)
        assertNull("the snapshot removed the contact", database.contactDao().getByUid("alice"))

        val sent = mutableListOf<ClientEncryptedMessage>()
        var vaultOpened = false
        val outcome = ClientEncryptedSender(
            opener = object : VaultOpener {
                override suspend fun open(): OpenOutcome = OpenOutcome.Failed("unused").also { vaultOpened = true }
                override fun sealedKind(): VaultRecordKind? = null
            },
            resolver = { addresses -> ResolveResult.Success(addresses.map { ResolvedRecipientKey(it, KEY_B, "", "discovered", true) }) },
            transport = { message -> sent += message; MailOutcome.Success(MailSendOutcome(true, "")) },
            localKeys = RoomLocalSignerKeys { database },
            accountAddress = "me@example.invalid",
        ).send(MailDraft(to = "alice@example.invalid", subject = "s", body = "b", mode = "plain"), sign = false)

        assertTrue("expected KeyChanged, got $outcome", outcome is ClientSendOutcome.KeyChanged)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    private companion object {
        const val TEST_DB = "legacy-key-migration-test"
        val KEY_A: String by lazy { publicKey("A <alice@example.invalid>") }
        val KEY_B: String by lazy { publicKey("B <alice@example.invalid>") }

        @Suppress("DEPRECATION")
        fun publicKey(uid: String): String {
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
}
