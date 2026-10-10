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
    }
}
