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

    /** The relay's `GET /api/groups` after the user deleted every group. */
    private val noGroups = OkHttpClient.Builder().addInterceptor(
        Interceptor { chain ->
            Response.Builder().request(chain.request()).protocol(Protocol.HTTP_1_1).code(200).message("OK")
                .body("""{"groups":[]}""".toResponseBody("application/json".toMediaType())).build()
        },
    ).build()

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
}
