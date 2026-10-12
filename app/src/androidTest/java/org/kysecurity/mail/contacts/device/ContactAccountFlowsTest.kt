package org.kysecurity.mail.contacts.device

import android.Manifest
import android.accounts.AccountManager
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.provider.ContactsContract
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.ContactsListActivity
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.xmlpull.v1.XmlPullParser
import java.util.concurrent.TimeUnit

/** What the platform and Settings ask of the contacts account: an edit schema contacts apps can
 *  find, and authenticator calls that always answer their caller. */
@RunWith(AndroidJUnit4::class)
class ContactAccountFlowsTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val accounts = DeviceContactAccountManager(context)

    @Before
    fun grant() {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
    }

    @After
    fun tearDown() {
        DeviceContactSyncSettings(context).setEnabled(false)
        DeviceContactSyncScheduler.cancelPeriodic(context)
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
        PendingAccountSetup.cancel()
        // androidTest/AGENTS.md: release the runtime graphs activity fixtures initialised.
        DeviceContactsRuntime.invalidate()
        org.kysecurity.mail.contacts.ContactsRuntime.invalidate()
    }

    /** AOSP Contacts reads CONTACTS_STRUCTURE off the service answering android.content.SyncAdapter. */
    @Test
    fun theEditSchemaIsWiredOnTheSyncAdapterService() {
        val pm = context.packageManager
        val service = pm.queryIntentServices(
            Intent("android.content.SyncAdapter").setPackage(context.packageName),
            PackageManager.GET_META_DATA,
        ).single().serviceInfo
        val parser = service.loadXmlMetaData(pm, "android.provider.CONTACTS_STRUCTURE")
        assertNotNull("no android.provider.CONTACTS_STRUCTURE on ${service.name}", parser)

        val tags = mutableListOf<String>()
        parser!!.use {
            while (it.next() != XmlPullParser.END_DOCUMENT) if (it.eventType == XmlPullParser.START_TAG) tags += it.name
        }
        assertEquals("ContactsAccountType", tags.first())
        assertEquals(true, "EditSchema" in tags)
        assertEquals(ContactsContract.AUTHORITY, "com.android.contacts")
    }

    @Test
    fun editProperties_answersItsCaller() {
        val result = AccountManager.get(context)
            .editProperties(DeviceContactAccount.ACCOUNT_TYPE, null, null, null)
            .getResult(10, TimeUnit.SECONDS)

        assertNotNull(result)
    }

    /** Settings' "Add account": the future it waits on completes with the account the flow adds. */
    @Test
    fun addAccount_fromAnActivity_completesWithTheAccount() {
        accounts.removeAccountBlocking()
        DeviceContactSyncSettings(context).setEnabled(false)
        var caller: Activity? = null
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { caller = it }

            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val monitor = instrumentation.addMonitor(ContactsListActivity::class.java.name, null, false)
            val future = AccountManager.get(context)
                .addAccount(DeviceContactAccount.ACCOUNT_TYPE, null, null, null, caller, null, null)
            // The screen AccountManager opens asks first; the user's Enable is what adds the account.
            val setup = instrumentation.waitForMonitorWithTimeout(monitor, 15_000) as ContactsListActivity?
            instrumentation.removeMonitor(monitor)
            assertNotNull("the setup screen was not opened", setup)
            instrumentation.waitForIdleSync()
            instrumentation.runOnMainSync {
                setup!!.setupDialog!!.getButton(android.content.DialogInterface.BUTTON_POSITIVE).performClick()
            }
            val result = future.getResult(30, TimeUnit.SECONDS)

            assertEquals(DeviceContactAccount.ACCOUNT_NAME, result.getString(AccountManager.KEY_ACCOUNT_NAME))
            assertEquals(DeviceContactAccount.ACCOUNT_TYPE, result.getString(AccountManager.KEY_ACCOUNT_TYPE))
        }
    }
}
