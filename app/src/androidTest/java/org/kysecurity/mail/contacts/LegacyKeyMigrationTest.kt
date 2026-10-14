package org.kysecurity.mail.contacts

import androidx.room.Room
import androidx.room.testing.MigrationTestHelper
import androidx.sqlite.db.framework.FrameworkSQLiteOpenHelperFactory
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

    /** One v12 contact row for Alice: [key] stored beside [fingerprint], alarmed or not. */
    private data class V12Row(val uid: String, val key: String, val fingerprint: String?, val alarmed: Boolean = false)

    /** A v12 database holding [rows] in that order, upgraded to the current schema. */
    private fun upgradedV12(rows: List<V12Row> = listOf(V12Row("alice", KEY_A, PgpFingerprint.compute(KEY_A)))): AppDatabase {
        helper.createDatabase(TEST_DB, 12).apply {
            for (row in rows) {
                execSQL(
                    "INSERT INTO contacts (uid, rev, fn, emailsJson, phonesJson, addressesJson, pgpKey, pgpKeyFingerprint, " +
                        "pgpKeyNeedsReverification) VALUES (?, 3, 'Alice', ?, '[]', '[]', ?, ?, ?)",
                    arrayOf<Any?>(row.uid, """[{"value":"Alice@Example.invalid"}]""", row.key, row.fingerprint, if (row.alarmed) 1 else 0),
                )
            }
            close()
        }
        return Room.databaseBuilder(context, AppDatabase::class.java, TEST_DB)
            .addMigrations(AppDatabase.MIGRATION_12_13, AppDatabase.MIGRATION_13_14, AppDatabase.MIGRATION_14_15, AppDatabase.MIGRATION_15_16, AppDatabase.MIGRATION_16_17, AppDatabase.MIGRATION_17_18)
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

    /** Two v12 rows share an address and a stored fingerprint, as after a key the fingerprint check
     *  rejected kept the previous fingerprint: a confirmed valid key and an alarmed different key.
     *  Whatever order they are read in, the alarmed key must not take the other row's confirmation. */
    @Test
    fun anAlarmedKeyNeverInheritsAnotherRowsConfirmation() = runBlocking {
        val shared = PgpFingerprint.compute(KEY_A)
        val confirmed = V12Row("alice", KEY_A, shared)
        val alarmed = V12Row("alice-2", KEY_B, shared, alarmed = true)
        for (rows in listOf(listOf(confirmed, alarmed), listOf(alarmed, confirmed))) {
            val database = upgradedV12(rows)
            val keys = RoomLocalSignerKeys { database }.keysFor("alice@example.invalid")
            fun verdict(key: String) = signatureStateFor(RawSignature.Checked(ring(key).publicKey.keyID, verified = true), emptyList(), keys)
            val order = rows.map { it.uid }

            assertNotEquals("alarmed key, rows $order", PgpSignatureState.VERIFIED_CONFIRMED, verdict(KEY_B))
            assertEquals("confirmed key, rows $order", PgpSignatureState.VERIFIED_CONFIRMED, verdict(KEY_A))
            database.close()
            db = null
            context.deleteDatabase(TEST_DB)
        }
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
        assertEquals(ClientSendOutcome.RecipientKeyRevoked(listOf("alice@example.invalid")), outcome)
        assertEquals(emptyList<ClientEncryptedMessage>(), sent)
        assertEquals(false, vaultOpened)
    }

    private companion object {
        const val TEST_DB = "legacy-key-migration-test"
        val SECRET_A by lazy { RevocationTestKeys.secretRing("A <alice@example.invalid>") }
        val KEY_A: String by lazy { RevocationTestKeys.public(SECRET_A) }
        val KEY_B: String by lazy { RevocationTestKeys.public(RevocationTestKeys.secretRing("B <alice@example.invalid>")) }

        /** [KEY_A] with a key revocation made by its own primary key. */
        val REVOKED_A: String by lazy { RevocationTestKeys.primaryRevoked(SECRET_A, signer = SECRET_A) }

        fun ring(armoredKey: String) = RevocationTestKeys.ring(armoredKey)
    }
}
