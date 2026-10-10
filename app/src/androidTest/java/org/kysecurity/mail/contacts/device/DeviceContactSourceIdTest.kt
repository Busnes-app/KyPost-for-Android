package org.kysecurity.mail.contacts.device

import android.Manifest
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
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The raw contact carries its uid in SOURCE_ID, so a lost link row is rebuilt, not duplicated. */
@RunWith(AndroidJUnit4::class)
class DeviceContactSourceIdTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val accounts = DeviceContactAccountManager(context)
    private lateinit var db: AppDatabase
    private lateinit var syncRepository: ContactSyncRepository
    private lateinit var repository: DeviceContactRepository

    @Before
    fun setUp() = runBlocking {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        check(accounts.ensureAccount()) { "needs a sync account; is the device unlocked?" }
        DeviceContactPurge.deleteSyncedRows(context)

        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
        syncRepository = ContactSyncRepository(
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
    }

    @After
    fun tearDown() {
        db.close()
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
    }

    private fun ownRowsFor(uid: String): Int = context.contentResolver.query(
        ContactsContract.RawContacts.CONTENT_URI,
        arrayOf(ContactsContract.RawContacts._ID),
        "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ? AND ${ContactsContract.RawContacts.SOURCE_ID} = ? AND " +
            "${ContactsContract.RawContacts.DELETED} = 0",
        arrayOf(DeviceContactAccount.ACCOUNT_TYPE, uid),
        null,
    )?.use { it.count } ?: 0

    private fun ownRowCount(): Int = context.contentResolver.query(
        ContactsContract.RawContacts.CONTENT_URI,
        arrayOf(ContactsContract.RawContacts._ID),
        "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ? AND ${ContactsContract.RawContacts.DELETED} = 0",
        arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
        null,
    )?.use { it.count } ?: 0

    @Test
    fun aLostLinkRow_isRebuiltFromSourceId_notDuplicated() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Source Id Probe", emails = listOf()))
        repository.syncAll()
        assertEquals("first sync writes the raw contact with its uid", 1, ownRowsFor(uid))
        val before = ownRowCount()

        // Process death between the CP2 insert and the link write, or "Clear data".
        db.deviceContactLinkDao().deleteAll()
        repository.syncAll()

        assertEquals("the second sync must adopt the existing row", before, ownRowCount())
        assertEquals(1, ownRowsFor(uid))
        assertEquals("the link is rebuilt", 1, db.deviceContactLinkDao().getAll().count { it.uid == uid })
    }

    private fun deviceDisplayName(rawContactId: Long): String? = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE),
        null,
    )?.use { if (it.moveToFirst()) it.getString(0) else null }

    /** A phone edit made while the link was lost is newer than Room's copy and must win, not be
     *  overwritten when the row is adopted back. */
    @Test
    fun aPhoneEditMadeWhileTheLinkWasLost_survivesAdoption() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Old Name", updatedAt = "2020-01-01T00:00:00Z"))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        db.deviceContactLinkDao().deleteAll()
        // An ordinary edit, as the system Contacts app makes one: the row becomes dirty.
        context.contentResolver.update(
            ContactsContract.Data.CONTENT_URI,
            android.content.ContentValues().apply {
                put(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, "New Name")
            },
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
            arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE),
        )

        repository.syncAll()

        assertEquals("New Name", db.contactDao().getByUid(uid)!!.fn)
        assertEquals("New Name", deviceDisplayName(rawContactId))
        assertEquals("no duplicate row", 1, ownRowsFor(uid))
    }
}
