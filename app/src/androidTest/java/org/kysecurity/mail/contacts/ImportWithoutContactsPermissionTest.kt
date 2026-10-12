package org.kysecurity.mail.contacts

import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.device.DeviceContactAccountManager
import org.kysecurity.mail.contacts.device.DeviceContactPurge
import org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler
import org.kysecurity.mail.contacts.device.DeviceContactSyncSettings
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.junit.After
import org.junit.Before
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Contacts permission can be revoked in Android settings while device sync stays switched on.
 *  The provider then refuses the account query; choosing Import must not crash the app. Revoking
 *  the real permission kills the test process, so the query stands in for the provider. */
@RunWith(AndroidJUnit4::class)
class ImportWithoutContactsPermissionTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    /** Granted, so the recovery re-enables sync in place instead of raising the system permission
     *  dialog, which would cover the screen and outlive this test. The refusal comes from the seam. */
    @Before
    fun grant() {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, android.Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, android.Manifest.permission.WRITE_CONTACTS)
    }

    @After
    fun tearDown() {
        DeviceContactSyncSettings(context).setEnabled(false)
        DeviceContactSyncScheduler.cancelPeriodic(context)
        DeviceContactPurge.deleteSyncedRows(context)
        DeviceContactAccountManager(context).removeAccountBlocking()
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
    }

    @Test
    fun importWithTheProviderRefusingTheQuery_keepsTheScreenAlive() {
        ActivityScenario.launch(ContactsListActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.foreignAccounts = { throw SecurityException("Permission Denial: reading contacts") }
                activity.showImportAccounts()
            }
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            assertEquals(Lifecycle.State.RESUMED, scenario.state)
        }
    }
}
