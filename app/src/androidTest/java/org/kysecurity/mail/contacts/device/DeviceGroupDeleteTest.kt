package org.kysecurity.mail.contacts.device

import android.Manifest
import android.provider.ContactsContract
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.ContactCursorStore
import org.kysecurity.mail.contacts.ContactSyncClient
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.GroupSyncRepository
import org.kysecurity.mail.contacts.GroupsSyncClient
import org.kysecurity.mail.contacts.TEST_PAIRING
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.runBlocking
import okhttp3.Interceptor
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** A group deleted on the server leaves the phone's address book on the next refresh. */
@RunWith(AndroidJUnit4::class)
class DeviceGroupDeleteTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val accounts = DeviceContactAccountManager(context)
    private lateinit var db: AppDatabase

    /** The relay, answering `GET /api/groups` with [groupsJson]. */
    private fun relay(groupsJson: String) = OkHttpClient.Builder().addInterceptor(
        Interceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body("""{"groups":$groupsJson}""".toResponseBody("application/json".toMediaType())).build()
        },
    ).build()

    /** After the user deleted every group. */
    private val noGroups = relay("[]")

    private fun repositoryAgainst(client: OkHttpClient) = DeviceContactRepository(
        context = context,
        db = db,
        syncRepository = ContactSyncRepository(
            db = db,
            client = ContactSyncClient(callFactory = client),
            cursorStore = ContactCursorStore(context, db),
            pairingProvider = { null },
        ),
        groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = client)) { TEST_PAIRING },
    )

    @Before
    fun setUp() = runBlocking {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        check(accounts.ensureAccount()) { "needs a sync account; is the device unlocked?" }
        db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()
    }

    @After
    fun tearDown() {
        db.close()
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
    }

    private fun groupRows(rowId: Long): Int = context.contentResolver.query(
        ContactsContract.Groups.CONTENT_URI,
        arrayOf(ContactsContract.Groups._ID),
        "${ContactsContract.Groups._ID} = ? AND ${ContactsContract.Groups.DELETED} = 0",
        arrayOf(rowId.toString()),
        null,
    )?.use { it.count } ?: 0

    @Test
    fun aGroupGoneFromTheServer_isRemovedFromThePhone() = runBlocking {
        val rowId = DeviceGroupLinker(context, db).ensureAndroidGroupRowId("g-gone", "Group Delete Probe")!!
        assertEquals(1, groupRows(rowId))

        val repository = DeviceContactRepository(
            context = context,
            db = db,
            syncRepository = ContactSyncRepository(
                db = db,
                client = ContactSyncClient(callFactory = noGroups),
                cursorStore = ContactCursorStore(context, db),
                pairingProvider = { null },
            ),
            groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = noGroups)) { TEST_PAIRING },
        )
        repository.syncAll()

        assertEquals(0, groupRows(rowId))
        assertEquals(null, db.groupLinkDao().getByGroupId("g-gone"))
    }

    /** Two backend groups with one title share a device row; deleting one keeps the row. */
    @Test
    fun aDeviceRowSharedByASurvivingGroup_isKept_withItsMemberships() = runBlocking {
        val linker = DeviceGroupLinker(context, db)
        val rowId = linker.ensureAndroidGroupRowId("g-kept", "Shared Title Probe")!!
        assertEquals("title matching shares the row", rowId, linker.ensureAndroidGroupRowId("g-gone", "Shared Title Probe"))
        val member = insertOwnRawContactInGroup(rowId)

        repositoryAgainst(relay("""[{"id":"g-kept","name":"Shared Title Probe","rev":1}]""")).syncAll()

        assertEquals(1, groupRows(rowId))
        assertEquals(rowId, db.groupLinkDao().getByGroupId("g-kept")?.androidGroupRowId)
        assertEquals(null, db.groupLinkDao().getByGroupId("g-gone"))
        assertEquals(listOf(rowId), membershipsOf(member))
    }

    /** The removal is scoped to this app's account type: a stale link pointing at another
     *  account's group cannot delete it. The other group is the phone's own (no account): one
     *  under an account type AccountManager does not know is swept by CP2 itself whenever the
     *  account list changes, which made this test depend on timing. */
    @Test
    fun aGroupOfAnotherAccountType_survivesRemoval() = runBlocking {
        val foreign = context.contentResolver.insert(
            ContactsContract.Groups.CONTENT_URI,
            android.content.ContentValues().apply { put(ContactsContract.Groups.TITLE, "Foreign Group Probe") },
        )!!.lastPathSegment!!.toLong()
        try {
            db.groupLinkDao().upsert(org.kysecurity.mail.data.GroupLinkEntity(groupId = "g-stale", androidGroupRowId = foreign))

            repositoryAgainst(noGroups).syncAll()

            assertEquals(1, groupRows(foreign))
        } finally {
            context.contentResolver.delete(
                ContactsContract.Groups.CONTENT_URI.buildUpon()
                    .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build(),
                "${ContactsContract.Groups._ID} = ?",
                arrayOf(foreign.toString()),
            )
        }
    }

    private fun insertOwnRawContactInGroup(groupRowId: Long): Long {
        val raw = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build()
        val data = ContactsContract.Data.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build()
        val results = context.contentResolver.applyBatch(
            ContactsContract.AUTHORITY,
            arrayListOf(
                android.content.ContentProviderOperation.newInsert(raw)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
                    .build(),
                android.content.ContentProviderOperation.newInsert(data)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(ContactsContract.Data.MIMETYPE, ContactsContract.CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE)
                    .withValue(ContactsContract.CommonDataKinds.GroupMembership.GROUP_ROW_ID, groupRowId)
                    .build(),
            ),
        )
        return results[0].uri!!.lastPathSegment!!.toLong()
    }

    private fun membershipsOf(rawContactId: Long): List<Long> = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(ContactsContract.CommonDataKinds.GroupMembership.GROUP_ROW_ID),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.GroupMembership.CONTENT_ITEM_TYPE),
        null,
    )?.use { c -> buildList { while (c.moveToNext()) add(c.getLong(0)) } }.orEmpty()
}
