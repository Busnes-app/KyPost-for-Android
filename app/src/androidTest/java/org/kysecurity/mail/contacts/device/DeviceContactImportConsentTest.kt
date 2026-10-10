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
    private lateinit var repository: DeviceContactRepository
    private var localRawContactId = 0L

    @Before
    fun setUp() = runBlocking {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        check(accounts.ensureAccount()) { "needs a sync account; is the device unlocked?" }
        settings.setImportAccounts(emptySet())
        settings.setLastForeignScanAtEpochMs(0L)

        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        val syncRepository = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = OkHttpClient()),
            cursorStore = ContactCursorStore(context, db),
            pairingProvider = { null },
        )
        repository = DeviceContactRepository(
            context = context,
            db = db,
            syncRepository = syncRepository,
            groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = OkHttpClient())) { null },
        )
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
        settings.setImportAccounts(emptySet())
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
    }

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

    private suspend fun queuedProbeCreates(): Int = db.pendingContactChangeDao().getAllPending()
        .filter { it.changeType == ContactSyncRepository.CHANGE_CREATE }
        .count { Json { ignoreUnknownKeys = true }.decodeFromString(ContactDto.serializer(), it.payloadJson).fn == PROBE_NAME }

    @Test
    fun withoutConsent_nothingFromAnotherAccountIsQueuedForUpload() = runBlocking {
        repository.syncAll()

        assertEquals(0, queuedProbeCreates())
    }

    @Test
    fun consentingToAnAccount_importsItsExistingContacts() = runBlocking {
        repository.syncAll()
        // The first sync already moved the scan watermark past the probe; consent must rewind it.
        val local = repository.foreignContactAccounts().single { it.type == null && it.name == null }
        settings.setImportAccounts(setOf(local.key))
        repository.syncAll()

        assertEquals(1, queuedProbeCreates())
    }

    private companion object {
        const val PROBE_NAME = "Import Consent Probe"
    }
}
