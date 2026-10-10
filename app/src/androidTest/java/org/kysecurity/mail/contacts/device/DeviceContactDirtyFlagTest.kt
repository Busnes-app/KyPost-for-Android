package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.ContentValues
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

/** An edit that lands after the sync read a row must keep that row dirty. */
@RunWith(AndroidJUnit4::class)
class DeviceContactDirtyFlagTest {
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

    private fun dirtyAndVersion(rawContactId: Long): Pair<Int, Long> = context.contentResolver.query(
        ContactsContract.RawContacts.CONTENT_URI,
        arrayOf(ContactsContract.RawContacts.DIRTY, ContactsContract.RawContacts.VERSION),
        "${ContactsContract.RawContacts._ID} = ?",
        arrayOf(rawContactId.toString()),
        null,
    )!!.use { it.moveToFirst(); it.getInt(0) to it.getLong(1) }

    /** An ordinary (non-sync-adapter) edit, as the system Contacts app makes: sets DIRTY, bumps VERSION. */
    private fun userEdit(rawContactId: Long, note: String) {
        context.contentResolver.insert(
            ContactsContract.Data.CONTENT_URI,
            ContentValues().apply {
                put(ContactsContract.Data.RAW_CONTACT_ID, rawContactId)
                put(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.Note.CONTENT_ITEM_TYPE)
                put(ContactsContract.CommonDataKinds.Note.NOTE, note)
            },
        )
    }

    @Test
    fun clearingDirty_atAStaleVersion_leavesTheRowDirty() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Dirty Flag Probe"))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId

        userEdit(rawContactId, "first")
        val (_, readVersion) = dirtyAndVersion(rawContactId)
        userEdit(rawContactId, "second") // lands after the sync read the row

        repository.clearDirtyFlag(rawContactId, readVersion)
        assertEquals("the later edit must still be pending", 1, dirtyAndVersion(rawContactId).first)

        repository.clearDirtyFlag(rawContactId, dirtyAndVersion(rawContactId).second)
        assertEquals(0, dirtyAndVersion(rawContactId).first)
    }
}
