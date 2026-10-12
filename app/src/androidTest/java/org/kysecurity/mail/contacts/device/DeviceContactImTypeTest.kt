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
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactSyncClient
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.ContactUrlDto
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

/** IM, website, relation and event rows are rebuilt when their list changes; the phone's own
 *  type, label or protocol on a kept row is not something Room carries, so the rebuild must keep
 *  it. */
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

    private fun setImType(rawContactId: Long, protocolLabel: String, type: Int, label: String?) {
        context.contentResolver.update(
            dataAsAdapter,
            ContentValues().apply {
                put(ContactsContract.CommonDataKinds.Im.TYPE, type)
                put(ContactsContract.CommonDataKinds.Im.LABEL, label)
            },
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ? AND " +
                "${ContactsContract.CommonDataKinds.Im.CUSTOM_PROTOCOL} = ?",
            arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE, protocolLabel),
        )
    }

    /** Type and label per protocol: a number on Signal and the same number on Telegram can be
     *  filed differently, and each keeps its own. */
    private fun imTypesByProtocol(rawContactId: Long): Map<String, Pair<Int?, String?>> = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(
            ContactsContract.CommonDataKinds.Im.CUSTOM_PROTOCOL,
            ContactsContract.CommonDataKinds.Im.TYPE,
            ContactsContract.CommonDataKinds.Im.LABEL,
        ),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE),
        null,
    )?.use { c ->
        buildMap { while (c.moveToNext()) put(c.getString(0), (if (c.isNull(1)) null else c.getInt(1)) to c.getString(2)) }
    }.orEmpty()

    @Test
    fun theSameValueOnTwoServices_keepsEachServicesType() = runBlocking {
        val uid = syncRepository.queueCreate(
            ContactDto(
                fn = "Im Service Probe",
                ims = listOf(
                    ContactImDto(service = "signal", value = "+15550100"),
                    ContactImDto(service = "telegram", value = "+15550100"),
                ),
            ),
        )
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        setImType(rawContactId, "Signal", ContactsContract.CommonDataKinds.Im.TYPE_HOME, null)
        setImType(rawContactId, "Telegram", ContactsContract.CommonDataKinds.Im.TYPE_CUSTOM, "Night line")

        val contact = db.contactDao().getByUid(uid)!!.toDto()
        syncRepository.queueUpdate(
            contact.copy(ims = contact.ims + ContactImDto(service = "matrix", value = "@probe:example.org")),
            identityChanged = false,
        )
        repository.syncAll()

        val types = imTypesByProtocol(rawContactId)
        assertEquals(ContactsContract.CommonDataKinds.Im.TYPE_HOME to null, types["Signal"])
        assertEquals(ContactsContract.CommonDataKinds.Im.TYPE_CUSTOM to "Night line", types["Telegram"])
    }

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

    /** A row with no protocol is an "Other" IM, which the rebuild writes as "Other"; the kept
     *  type must be found under that same protocol. */
    @Test
    fun anImWithNoProtocol_keepsItsWorkTypeAfterAnAppend() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Im Protocol Probe", ims = listOf(ContactImDto(service = "", value = "probe-im"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        context.contentResolver.update(
            dataAsAdapter,
            ContentValues().apply {
                putNull(ContactsContract.CommonDataKinds.Im.CUSTOM_PROTOCOL)
                put(ContactsContract.CommonDataKinds.Im.TYPE, ContactsContract.CommonDataKinds.Im.TYPE_WORK)
            },
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
        assertEquals("both IMs are on the phone", setOf("probe-im", "@second:example.org"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Im.TYPE_WORK, types["probe-im"])
    }

    private fun websiteTypes(rawContactId: Long): Map<String, Pair<Int?, String?>> = context.contentResolver.query(
        ContactsContract.Data.CONTENT_URI,
        arrayOf(
            ContactsContract.CommonDataKinds.Website.URL,
            ContactsContract.CommonDataKinds.Website.TYPE,
            ContactsContract.CommonDataKinds.Website.LABEL,
        ),
        "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
        arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE),
        null,
    )?.use { c ->
        buildMap { while (c.moveToNext()) put(c.getString(0), (if (c.isNull(1)) null else c.getInt(1)) to c.getString(2)) }
    }.orEmpty()

    /** Website rows are rebuilt the same way, and Room has no slot for the phone's Work type. */
    @Test
    fun appendingAWebsiteInRoom_keepsTheExistingWebsitesWorkType() = runBlocking {
        val uid = syncRepository.queueCreate(
            ContactDto(fn = "Website Type Probe", websites = listOf(ContactUrlDto(value = "https://one.example.invalid"))),
        )
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        context.contentResolver.update(
            dataAsAdapter,
            ContentValues().apply {
                put(ContactsContract.CommonDataKinds.Website.TYPE, ContactsContract.CommonDataKinds.Website.TYPE_WORK)
                putNull(ContactsContract.CommonDataKinds.Website.LABEL)
            },
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
            arrayOf(rawContactId.toString(), ContactsContract.CommonDataKinds.Website.CONTENT_ITEM_TYPE),
        )

        val contact = db.contactDao().getByUid(uid)!!.toDto()
        syncRepository.queueUpdate(
            contact.copy(websites = contact.websites + ContactUrlDto(value = "https://two.example.invalid")),
            identityChanged = false,
        )
        repository.syncAll()

        val types = websiteTypes(rawContactId)
        assertEquals("both websites are on the phone", setOf("https://one.example.invalid", "https://two.example.invalid"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Website.TYPE_WORK to null, types["https://one.example.invalid"])
    }

    /** [column] of each row of [mimeType], keyed by its [keyColumn]. */
    private fun columnByKey(rawContactId: Long, mimeType: String, keyColumn: String, column: String): Map<String, String?> =
        context.contentResolver.query(
            ContactsContract.Data.CONTENT_URI,
            arrayOf(keyColumn, column),
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ?",
            arrayOf(rawContactId.toString(), mimeType),
            null,
        )?.use { c -> buildMap { while (c.moveToNext()) put(c.getString(0), c.getString(1)) } }.orEmpty()

    /** Sets [values] on the [mimeType] rows of [rawContactId] whose [keyColumn] is [key], as the
     *  phone's own Contacts app would file them. Room's view of the row does not change. */
    private fun setColumns(rawContactId: Long, mimeType: String, keyColumn: String, key: String, values: ContentValues) {
        context.contentResolver.update(
            dataAsAdapter,
            values,
            "${ContactsContract.Data.RAW_CONTACT_ID} = ? AND ${ContactsContract.Data.MIMETYPE} = ? AND $keyColumn = ?",
            arrayOf(rawContactId.toString(), mimeType, key),
        )
    }

    /** Appends [change] to the contact in Room and syncs, so every row of that kind is rebuilt. */
    private suspend fun appendInRoomAndSync(uid: String, change: (ContactDto) -> ContactDto) {
        syncRepository.queueUpdate(change(db.contactDao().getByUid(uid)!!.toDto()), identityChanged = false)
        repository.syncAll()
    }

    /** A built-in protocol has no custom label; Room reads it as "other", and a rebuild must not
     *  turn it into a custom "Other". */
    @Test
    fun aJabberImKeepsItsProtocolWhenAnotherImIsAppended() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Im Protocol Kept Probe", ims = listOf(ContactImDto(service = "", value = "probe@jabber.example.invalid"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        val im = ContactsContract.CommonDataKinds.Im.CONTENT_ITEM_TYPE
        setColumns(rawContactId, im, ContactsContract.CommonDataKinds.Im.DATA, "probe@jabber.example.invalid", ContentValues().apply {
            put(ContactsContract.CommonDataKinds.Im.PROTOCOL, ContactsContract.CommonDataKinds.Im.PROTOCOL_JABBER)
            putNull(ContactsContract.CommonDataKinds.Im.CUSTOM_PROTOCOL)
        })

        appendInRoomAndSync(uid) { it.copy(ims = it.ims + ContactImDto(service = "matrix", value = "@second:example.org")) }

        val protocols = columnByKey(rawContactId, im, ContactsContract.CommonDataKinds.Im.DATA, ContactsContract.CommonDataKinds.Im.PROTOCOL)
        assertEquals("both IMs are on the phone", setOf("probe@jabber.example.invalid", "@second:example.org"), protocols.keys)
        assertEquals(ContactsContract.CommonDataKinds.Im.PROTOCOL_JABBER.toString(), protocols["probe@jabber.example.invalid"])
    }

    /** Brother has no Room label of its own: it reads as "other" and must not be written back as
     *  a custom "other". */
    @Test
    fun aBrotherRelationKeepsItsTypeWhenAnotherRelationIsAppended() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Relation Type Kept Probe", relations = listOf(ContactRelationDto(label = "other", name = "Probe Brother"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        val relation = ContactsContract.CommonDataKinds.Relation.CONTENT_ITEM_TYPE
        setColumns(rawContactId, relation, ContactsContract.CommonDataKinds.Relation.NAME, "Probe Brother", ContentValues().apply {
            put(ContactsContract.CommonDataKinds.Relation.TYPE, ContactsContract.CommonDataKinds.Relation.TYPE_BROTHER)
            putNull(ContactsContract.CommonDataKinds.Relation.LABEL)
        })

        appendInRoomAndSync(uid) { it.copy(relations = it.relations + ContactRelationDto(label = "friend", name = "Probe Friend")) }

        val types = columnByKey(rawContactId, relation, ContactsContract.CommonDataKinds.Relation.NAME, ContactsContract.CommonDataKinds.Relation.TYPE)
        assertEquals("both relations are on the phone", setOf("Probe Brother", "Probe Friend"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Relation.TYPE_BROTHER.toString(), types["Probe Brother"])
    }

    /** Room holds the relation with no label; the phone files it as Brother. The kept type is
     *  found under the same readback label Room's null reads back as, "other". */
    @Test
    fun anUnlabelledRelationKeepsThePhonesBrotherTypeWhenAnotherIsAppended() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Unlabelled Relation Probe", relations = listOf(ContactRelationDto(label = null, name = "Probe Sibling"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        val relation = ContactsContract.CommonDataKinds.Relation.CONTENT_ITEM_TYPE
        setColumns(rawContactId, relation, ContactsContract.CommonDataKinds.Relation.NAME, "Probe Sibling", ContentValues().apply {
            put(ContactsContract.CommonDataKinds.Relation.TYPE, ContactsContract.CommonDataKinds.Relation.TYPE_BROTHER)
            putNull(ContactsContract.CommonDataKinds.Relation.LABEL)
        })

        appendInRoomAndSync(uid) { it.copy(relations = it.relations + ContactRelationDto(label = "friend", name = "Probe Friend")) }

        val types = columnByKey(rawContactId, relation, ContactsContract.CommonDataKinds.Relation.NAME, ContactsContract.CommonDataKinds.Relation.TYPE)
        assertEquals("both relations are on the phone", setOf("Probe Sibling", "Probe Friend"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Relation.TYPE_BROTHER.toString(), types["Probe Sibling"])
    }

    /** An unlabelled Other event reads with no label and must not be written back as custom. */
    @Test
    fun anOtherEventKeepsItsTypeWhenAnotherEventIsAppended() = runBlocking {
        val uid = syncRepository.queueCreate(ContactDto(fn = "Event Type Kept Probe", events = listOf(ContactEventDto(label = null, date = "2020-01-02"))))
        repository.syncAll()
        val rawContactId = db.deviceContactLinkDao().getByUid(uid)!!.rawContactId
        val event = ContactsContract.CommonDataKinds.Event.CONTENT_ITEM_TYPE
        setColumns(rawContactId, event, ContactsContract.CommonDataKinds.Event.START_DATE, "2020-01-02", ContentValues().apply {
            put(ContactsContract.CommonDataKinds.Event.TYPE, ContactsContract.CommonDataKinds.Event.TYPE_OTHER)
            putNull(ContactsContract.CommonDataKinds.Event.LABEL)
        })

        appendInRoomAndSync(uid) { it.copy(events = it.events + ContactEventDto(label = "anniversary", date = "2021-03-04")) }

        val types = columnByKey(rawContactId, event, ContactsContract.CommonDataKinds.Event.START_DATE, ContactsContract.CommonDataKinds.Event.TYPE)
        assertEquals("both events are on the phone", setOf("2020-01-02", "2021-03-04"), types.keys)
        assertEquals(ContactsContract.CommonDataKinds.Event.TYPE_OTHER.toString(), types["2020-01-02"])
    }
}
