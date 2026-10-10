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
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactSyncClient
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.GroupSyncRepository
import org.kysecurity.mail.contacts.GroupsSyncClient
import org.kysecurity.mail.contacts.toDto
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The merge base may only advance once both sides hold the merged values, or a clear made on one
 *  side reads as "unchanged" there and the other side's stale value wins. */
@RunWith(AndroidJUnit4::class)
class DeviceContactMergeBaseTest {
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

    private fun deviceNotes(rawContactId: Long): List<String> = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(ContactsContract.CommonDataKinds.Note.NOTE),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Note.CONTENT_ITEM_TYPE),
        null,
    )?.use { c -> buildList { while (c.moveToNext()) c.getString(0)?.takeIf { it.isNotBlank() }?.let(::add) } }.orEmpty()

    /** An ordinary edit, as the system Contacts app makes one: marks the raw contact dirty. */
    private fun editDevicePhone(rawContactId: Long, number: String) {
        context.contentResolver.update(
            ContactsContract.Data.CONTENT_URI,
            ContentValues().apply { put(ContactsContract.CommonDataKinds.Phone.NUMBER, number) },
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
            arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Phone.CONTENT_ITEM_TYPE),
        )
    }

    @Test
    fun aNoteClearedInRoomWhileThePhoneIsEdited_isGoneFromBothSides() = runBlocking {
        val uid = syncRepository.queueCreate(
            ContactDto(fn = "Merge Base Probe", notes = "shared note", phones = listOf(ContactFieldDto(value = "+15550100"))),
        )
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        assertEquals("precondition: the note reached the phone", listOf("shared note"), deviceNotes(rawContactId))

        val cleared = db.contactDao().getByUid(uid)!!.toDto().copy(notes = null)
        syncRepository.queueUpdate(cleared, identityChanged = false)
        editDevicePhone(rawContactId, "+15550199")

        repository.syncAll()
        repository.syncAll()

        assertNull(db.contactDao().getByUid(uid)!!.notes?.takeIf { it.isNotBlank() })
        assertEquals(emptyList<String>(), deviceNotes(rawContactId))
        assertEquals("+15550199", db.contactDao().getByUid(uid)!!.toDto().phones.single().value)
    }
}
