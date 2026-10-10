package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.ContentProviderOperation
import android.provider.ContactsContract
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * A contact pushed to the device must be *displayable*, not merely stored. CP2 hides raw contacts
 * that belong to no group unless the account's Settings row sets UNGROUPED_VISIBLE, so a sync that
 * wrote every row correctly still showed the user an empty address book.
 */
@RunWith(AndroidJUnit4::class)
class DeviceContactVisibilityTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val resolver = context.contentResolver
    private val accounts = DeviceContactAccountManager(context)

    /**
     * `connectedAndroidTest` installs without runtime grants, and CP2 is not merely empty without
     * them — it refuses to open at all. Granted here rather than from the CI workflow so the test
     * carries its own setup; `androidx.test:rules` would buy the same thing for a new dependency.
     */
    @Before
    fun grantContactsAccessAndCreateAccount() = runBlocking {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        check(accounts.ensureAccount()) { "needs a sync account; is the device unlocked?" }
    }

    @After
    fun cleanup() {
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
    }

    private fun insertUngroupedRawContact(displayName: String): Long {
        val rawUri = ContactsContract.RawContacts.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build()
        val dataUri = ContactsContract.Data.CONTENT_URI.buildUpon()
            .appendQueryParameter(ContactsContract.CALLER_IS_SYNCADAPTER, "true").build()

        resolver.applyBatch(
            ContactsContract.AUTHORITY,
            arrayListOf(
                ContentProviderOperation.newInsert(rawUri)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_TYPE, DeviceContactAccount.ACCOUNT_TYPE)
                    .withValue(ContactsContract.RawContacts.ACCOUNT_NAME, DeviceContactAccount.ACCOUNT_NAME)
                    .build(),
                ContentProviderOperation.newInsert(dataUri)
                    .withValueBackReference(ContactsContract.Data.RAW_CONTACT_ID, 0)
                    .withValue(
                        ContactsContract.Data.MIMETYPE,
                        ContactsContract.CommonDataKinds.StructuredName.CONTENT_ITEM_TYPE,
                    )
                    .withValue(ContactsContract.CommonDataKinds.StructuredName.DISPLAY_NAME, displayName)
                    .build(),
            ),
        )

        return resolver.query(
            ContactsContract.RawContacts.CONTENT_URI,
            arrayOf(ContactsContract.RawContacts.CONTACT_ID),
            "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
            arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            null,
        )?.use { if (it.moveToFirst()) it.getLong(0) else null }
            ?: error("the raw contact we just inserted is not in the provider")
    }

    private fun inVisibleGroup(contactId: Long): Int = resolver.query(
        ContactsContract.Contacts.CONTENT_URI,
        arrayOf(ContactsContract.Contacts.IN_VISIBLE_GROUP),
        "${ContactsContract.Contacts._ID} = ?",
        arrayOf(contactId.toString()),
        null,
    )?.use { if (it.moveToFirst()) it.getInt(0) else null }
        ?: error("contact $contactId is missing from the aggregated Contacts table")

    private fun ungroupedVisible(): Int = resolver.query(
        ContactsContract.Settings.CONTENT_URI,
        arrayOf(ContactsContract.Settings.UNGROUPED_VISIBLE),
        "${ContactsContract.Settings.ACCOUNT_TYPE} = ?",
        arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
        null,
    )?.use { if (it.moveToFirst()) it.getInt(0) else 0 } ?: 0

    @Test
    fun ungroupedSyncedContact_isVisibleOnceTheAccountOptsIn() {
        val contactId = insertUngroupedRawContact("Visibility Probe")

        DeviceContactAccount.makeContactsVisible(context)

        assertEquals("the account must be opted in to showing ungrouped contacts", 1, ungroupedVisible())
        assertEquals(
            "a pushed contact that CP2 stores but hides is an empty address book to the user",
            1,
            inVisibleGroup(contactId),
        )
    }

    /** Every write notifies the contacts observer, which runs a sync, which runs this again. */
    @Test
    fun anAccountAlreadyVisible_isNotWrittenAgain() {
        DeviceContactAccount.makeContactsVisible(context)
        val notified = java.util.concurrent.CountDownLatch(1)
        val observer = object : android.database.ContentObserver(null) {
            override fun onChange(selfChange: Boolean) = notified.countDown()
        }
        resolver.registerContentObserver(ContactsContract.AUTHORITY_URI, true, observer)
        try {
            DeviceContactAccount.makeContactsVisible(context)

            assertEquals(
                "a no-op visibility check must not notify contact observers",
                false,
                notified.await(2, java.util.concurrent.TimeUnit.SECONDS),
            )
        } finally {
            resolver.unregisterContentObserver(observer)
        }
    }

    /** The fix runs on every sync, so a second write must update the row rather than add one. */
    @Test
    fun optingIn_isIdempotent() {
        DeviceContactAccount.makeContactsVisible(context)
        DeviceContactAccount.makeContactsVisible(context)

        val rows = resolver.query(
            ContactsContract.Settings.CONTENT_URI,
            arrayOf(ContactsContract.Settings.ACCOUNT_NAME),
            "${ContactsContract.Settings.ACCOUNT_TYPE} = ?",
            arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
            null,
        )?.use { it.count } ?: 0

        assertEquals("repeated opt-in must not duplicate the account's settings row", 1, rows)
        assertEquals(1, ungroupedVisible())
    }
}
