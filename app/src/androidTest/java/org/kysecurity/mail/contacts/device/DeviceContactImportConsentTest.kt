package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.ContentProviderOperation
import android.provider.ContactsContract
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.ContactCursorStore
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactSyncClient
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.GroupSyncRepository
import org.kysecurity.mail.contacts.GroupsSyncClient
import org.kysecurity.mail.contacts.TEST_PAIRING
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Contacts held by other accounts are uploaded to the server only from accounts the user chose. */
@RunWith(AndroidJUnit4::class)
class DeviceContactImportConsentTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val accounts = DeviceContactAccountManager(context)
    private val settings = DeviceContactSyncSettings(context)
    private lateinit var db: AppDatabase
    private lateinit var syncRepository: ContactSyncRepository
    private lateinit var repository: DeviceContactRepository
    private lateinit var destination: String
    private var localRawContactId = 0L

    @Before
    fun setUp() = runBlocking {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        check(accounts.ensureAccount()) { "needs a sync account; is the device unlocked?" }
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        syncRepository = syncRepositoryFor(TEST_PAIRING)
        destination = syncRepository.destination()!!
        settings.setImportAccounts(destination, emptySet())
        settings.setLastForeignScanAtEpochMs(0L)
        repository = deviceRepository(syncRepository)
        localRawContactId = insertLocalContact(PROBE_NAME, "consent-probe@example.com")
    }

    @After
    fun tearDown() {
        db.close()
        context.contentResolver.delete(
            ContactsContract.RawContacts.CONTENT_URI.buildUpon()
                .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build(),
            "${ContactsContract.RawContacts._ID} = ?",
            arrayOf(localRawContactId.toString()),
        )
        runBlocking { settings.setImportAccounts(destination, emptySet()) }
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
    }

    private fun syncRepositoryFor(pairing: org.kysecurity.mail.push.PairingData) = ContactSyncRepository(
        db = db,
        client = ContactSyncClient(callFactory = OkHttpClient()),
        cursorStore = ContactCursorStore(context, db),
        pairingProvider = { pairing },
    )

    private fun deviceRepository(sync: ContactSyncRepository, beforeImport: suspend () -> Unit = {}) =
        DeviceContactRepository(
            context = context,
            db = db,
            syncRepository = sync,
            groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = OkHttpClient())) { null },
            beforeImport = beforeImport,
        )

    /** A contact in the phone's own storage: no account at all. */
    private fun insertLocalContact(name: String, email: String): Long {
        val results = context.contentResolver.applyBatch(
            ContactsContract.AUTHORITY,
            arrayListOf(
                ContentProviderOperation.newInsert(ContactsContract.RawContacts.CONTENT_URI)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, null)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, null)
                    .build(),
                ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, name)
                    .build(),
                ContentProviderOperation.newInsert(ContactsContract.Data.CONTENT_URI)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Email.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.Email.ADDRESS, email)
                    .build(),
            ),
        )
        return results[0].uri!!.lastPathSegment!!.toLong()
    }

    private val json = Json { ignoreUnknownKeys = true }

    private suspend fun queuedProbeCreates(): Int = db.pendingContactChangeDao().getAllPending()
        .filter { it.changeType == ContactSyncRepository.CHANGE_CREATE }
        .count { json.decodeFromString(ContactDto.serializer(), it.payloadJson).fn == PROBE_NAME }

    /** What the import decides on, for a failure message: the probe row and the queue. */
    private suspend fun importState(): String {
        val row = context.contentResolver.query(
            ContactsContract.RawContacts.CONTENT_URI,
            arrayOf(
                ContactsContract.RawContacts.ACCOUNT_TYPE,
                ContactsContract.RawContacts.ACCOUNT_NAME,
                ContactsContract.RawContacts.CONTACT_ID,
                ContactsContract.RawContacts.DELETED,
            ),
            "${ContactsContract.RawContacts._ID} = ?",
            arrayOf(localRawContactId.toString()),
            null,
        )?.use { c -> if (c.moveToFirst()) "type=${c.getString(0)} name=${c.getString(1)} contact=${c.getLong(2)} deleted=${c.getInt(3)}" else "missing" }
        val queued = db.pendingContactChangeDao().getAllPending()
            .map { "${it.changeType}:" + runCatching { json.decodeFromString(ContactDto.serializer(), it.payloadJson).fn }.getOrNull() }
        return "probe[$row] accounts=${repository.foreignContactAccounts()} consent=${settings.importAccounts(destination)} " +
            "watermark=${settings.lastForeignScanAtEpochMs()} queued=$queued"
    }

    @Test
    fun withoutConsent_nothingFromAnotherAccountIsQueuedForUpload() = runBlocking {
        repository.syncAll()

        assertEquals(0, queuedProbeCreates())
    }

    /** A contact edited while the scan runs is newer than the scan's start, so it is seen next time. */
    @Test
    fun theNextWatermark_isWhenTheScanBegan() = runBlocking {
        settings.setImportAccounts(destination, setOf(DeviceAccount(null, null).key))
        val clocked = DeviceContactRepository(
            context = context,
            db = db,
            syncRepository = syncRepository,
            groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = OkHttpClient())) { null },
            now = { SCAN_STARTED_AT },
        )

        clocked.syncAll()

        assertEquals(SCAN_STARTED_AT, settings.lastForeignScanAtEpochMs())
    }

    @Test
    fun consentingToAnAccount_importsItsExistingContacts() = runBlocking {
        repository.syncAll()
        val local = repository.foreignContactAccounts().single { it.type == null && it.name == null }
        settings.setImportAccounts(destination, setOf(local.key))
        val failed = repository.syncAll()

        assertEquals("failed stages $failed; ${importState()}", 1, queuedProbeCreates())
    }

    @Test
    fun consentWithdrawnDuringAScan_importsNothing() = runBlocking {
        settings.setImportAccounts(destination, setOf(DeviceAccount(null, null).key))
        val scan = deviceRepository(syncRepository) { settings.setImportAccounts(destination, emptySet()) }

        scan.syncAll()

        assertEquals(0, queuedProbeCreates())
    }

    /** An account consented while a scan runs rewinds the watermark so its existing contacts are
     *  read; the scan, which started without that account, must not move the watermark past them
     *  when it ends. The second account here holds no contacts: what is checked is the rewind. */
    @Test
    fun anAccountAddedDuringAScan_keepsItsRewind() = runBlocking {
        val local = DeviceAccount(null, null).key
        val other = DeviceAccount("org.example.invalid", "other").key
        settings.setImportAccounts(destination, setOf(local))
        val scan = deviceRepository(syncRepository) { settings.setImportAccounts(destination, setOf(local, other)) }

        scan.syncAll()

        assertEquals("the probe was imported; ${importState()}", 1, queuedProbeCreates())
        assertEquals("the next scan reads everything again", 0L, settings.lastForeignScanAtEpochMs())
    }

    /** A pairing replacement lands while a scan runs: the session ends, the outbox is purged and a
     *  new pairing becomes active. Nothing consented under the old one may reach the new outbox. */
    @Test
    fun aPairingReplacedDuringAScan_queuesNothingForTheNewPairing() = runBlocking {
        settings.setImportAccounts(destination, setOf(DeviceAccount(null, null).key))
        var active = TEST_PAIRING
        val switching = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = OkHttpClient()),
            cursorStore = ContactCursorStore(context, db),
            pairingProvider = { active },
        )
        val scan = deviceRepository(switching) {
            org.kysecurity.mail.ProcessState.resetAll()
            db.pendingContactChangeDao().clearAll()
            active = TEST_PAIRING.copy(subscriberId = "sub-replacement")
        }

        scan.syncAll()

        assertEquals(0, queuedProbeCreates())
    }

    /** The account purge takes the consent lock and clears consent: an import already inside the
     *  lock finishes first (so the purge removes its row), and none can start after. */
    @Test
    fun theAccountPurge_waitsForAnImportInProgress_andLeavesNoConsent() = runBlocking {
        val key = DeviceAccount(null, null).key
        settings.setImportAccounts(destination, setOf(key))
        val order = java.util.Collections.synchronizedList(mutableListOf<String>())
        val inside = kotlinx.coroutines.CompletableDeferred<Unit>()
        val release = kotlinx.coroutines.CompletableDeferred<Unit>()
        val importing = launch(kotlinx.coroutines.Dispatchers.Default) {
            settings.whileConsented(destination, key) {
                inside.complete(Unit)
                release.await()
                order += "import"
            }
        }
        inside.await()
        val purging = launch(kotlinx.coroutines.Dispatchers.Default) { settings.clearConsentDuring { order += "purge" } }
        release.complete(Unit)
        importing.join()
        purging.join()

        assertEquals(listOf("import", "purge"), order.toList())
        assertEquals(null, settings.whileConsented(destination, key) { "queued" })
    }

    @Test
    fun consentGivenForOnePairing_doesNotCarryToAnother() = runBlocking {
        settings.setImportAccounts(destination, setOf(DeviceAccount(null, null).key))
        val otherSync = syncRepositoryFor(TEST_PAIRING.copy(subscriberId = "sub-2"))
        val otherServer = syncRepositoryFor(TEST_PAIRING.copy(serverUrl = "https://other.example.com"))

        assertEquals(emptySet<String>(), settings.importAccounts(otherSync.destination()!!))
        assertEquals(emptySet<String>(), settings.importAccounts(otherServer.destination()!!))
        deviceRepository(otherSync).syncAll()
        assertEquals(0, queuedProbeCreates())
    }

    private companion object {
        const val PROBE_NAME = "Import Consent Probe"
        const val SCAN_STARTED_AT = 42L
    }
}
