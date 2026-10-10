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

/** A contact gone from Room leaves the phone too, and a delete never lingers as a CP2 tombstone. */
@RunWith(AndroidJUnit4::class)
class DeviceContactDeleteTest {
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

    /** Rows for [uid], tombstoned or not. */
    private fun rowsFor(uid: String): Int = context.contentResolver.query(
        ContactsContract.RawContacts.CONTENT_URI,
        arrayOf(ContactsContract.RawContacts._ID),
        "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ? AND ${ContactsContract.RawContacts.SOURCE_ID} = ?",
        arrayOf(DeviceContactAccount.ACCOUNT_TYPE, uid),
        null,
    )?.use { it.count } ?: 0

    @Test
    fun aContactRemovedFromRoom_isRemovedFromThePhone() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Remote Delete Probe"))
        repository.syncAll()
        assertEquals(1, rowsFor(uid))

        // What applyDelta does for a server tombstone or a snapshot prune.
        db.contactDao().deleteByUids(listOf(uid))
        repository.syncAll()

        assertEquals(0, rowsFor(uid))
        assertEquals(null, db.deviceContactLinkDao().getByUid(uid))
    }

    @Test
    fun aDeleteMadeOnThePhone_isQueuedAndPurged() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Device Delete Probe"))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId

        // An ordinary (non-sync-adapter) delete only sets DELETED=1 and waits for the adapter.
        context.contentResolver.delete(
            ContactsContract.RawContacts.CONTENT_URI,
            "${ContactsContract.RawContacts._ID} = ?",
            arrayOf(rawContactId.toString()),
        )
        repository.syncAll()

        assertEquals("the tombstone must be purged", 0, rowsFor(uid))
        assertEquals(
            listOf(ContactSyncRepository.CHANGE_DELETE),
            db.pendingContactChangeDao().getByUid(uid).map { it.changeType },
        )
    }
}
