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
import org.kysecurity.mail.contacts.ContactImDto
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
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** IM rows are rebuilt when the list changes; the phone's own Home/Work type on a kept IM is not
 *  something Room carries, so the rebuild must keep it. */
@Suppress("DEPRECATION") // Im has no replacement mimetype; these are the rows on device.
@RunWith(AndroidJUnit4::class)
class DeviceContactImTypeTest {
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

    private val dataAsAdapter = ContactsContract.Data.CONTENT_URI.buildUpon()
        .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build()

    private fun imTypes(rawContactId: Long): Map<String, Int?> = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(ContactsContract.CommonDataKinds.Im.DATA, ContactsContract.CommonDataKinds.Im.TYPE),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE),
        null,
    )?.use { c -> buildMap { while (c.moveToNext()) put(c.getString(0), if (c.isNull(1)) null else c.getInt(1)) } }.orEmpty()

    @Test
    fun appendingAnImInRoom_keepsTheExistingImsWorkType() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Im Type Probe", ims = listOf(ContactImDto(service = "matrix", value = "@probe:example.org"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        // The phone files the IM under Work; Room has no field for that.
        context.contentResolver.update(
            dataAsAdapter,
            ContentValues().apply { put(ContactsContract.CommonDataKinds.Im.TYPE, ContactsContract.CommonDataKinds.Im.TYPE_WORK) },
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
            arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE),
        )

        val contact = db.contactDao().getByUid(uid)!!.toDto()
        syncRepository.queueUpdate(
            contact.copy(ims = contact.ims + ContactImDto(service = "matrix", value = "@second:example.org")),
            identityChanged = false,
        )
        repository.syncAll()

        val types = imTypes(rawContactId)
        assertEquals("both IMs are on the phone", setOf("@probe:example.org", "@second:example.org"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Im.TYPE_WORK, types["@probe:example.org"])
    }
}
