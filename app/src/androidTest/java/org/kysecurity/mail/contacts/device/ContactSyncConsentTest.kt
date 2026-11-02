package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.DialogInterface
import android.widget.TextView
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.SettingsActivity
import org.kysecurity.mail.contacts.ContactsRuntime

/** Google Play's prominent disclosure (#282), driven from Settings: it names the paired server,
 *  Agree records consent for that pairing and turns sync on, Not now or Back records nothing, and
 *  revoking turns sync off and forgets the consent. */
@RunWith(AndroidJUnit4::class)
class ContactSyncConsentTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val settings = DeviceContactSyncSettings(context)
    private val accounts = DeviceContactAccountManager(context)
    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Before
    fun setUp() {
        // Granted, so Agree enables in place instead of raising the system dialog.
        instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        instrumentation.uiAutomation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        runBlocking { settings.clearConsentDuring {} }
        accounts.removeAccountBlocking()
        pairForSyncTest(context)
    }

    @After
    fun tearDown() {
        unpairAfterSyncTest(context)
        DeviceContactSyncScheduler.cancelPeriodic(context)
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
    }

    private fun destination(): String = runBlocking { ContactsRuntime.graph(context).repository.destination()!! }

    private fun awaitDialog(scenario: ActivityScenario<SettingsActivity>): android.app.Dialog {
        var dialog: android.app.Dialog? = null
        val deadline = System.currentTimeMillis() + 10_000
        while (dialog == null && System.currentTimeMillis() < deadline) {
            instrumentation.waitForIdleSync()
            scenario.onActivity { dialog = it.contactSyncDialog?.takeIf { d -> d.isShowing } }
            if (dialog == null) android.os.SystemClock.sleep(50)
        }
        return dialog ?: throw AssertionError("no dialog")
    }

    private fun tapRow(scenario: ActivityScenario<SettingsActivity>) =
        scenario.onActivity { it.findViewById<android.view.View>(R.id.settingsContactSync).performClick() }

    private fun rowBody(scenario: ActivityScenario<SettingsActivity>): String {
        var body = ""
        scenario.onActivity { body = it.findViewById<TextView>(R.id.settingsContactSyncBody).text.toString() }
        return body
    }

    private fun awaitEnabled(expected: Boolean) {
        val deadline = System.currentTimeMillis() + 15_000
        while (settings.isEnabled() != expected && System.currentTimeMillis() < deadline) android.os.SystemClock.sleep(50)
        assertEquals(expected, settings.isEnabled())
    }

    private fun agree(scenario: ActivityScenario<SettingsActivity>) {
        tapRow(scenario)
        val dialog = awaitDialog(scenario) as androidx.appcompat.app.AlertDialog
        instrumentation.runOnMainSync { dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick() }
        awaitEnabled(true)
    }

    @Test
    fun agree_recordsConsentForTheNamedServerAndTurnsSyncOn() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            instrumentation.waitForIdleSync()
            tapRow(scenario)
            val dialog = awaitDialog(scenario) as androidx.appcompat.app.AlertDialog
            val message = dialog.findViewById<TextView>(android.R.id.message)!!.text.toString()
            assertTrue(message, "upload them to your KyPost server at $TEST_SYNC_SERVER" in message)
            assertEquals("Agree", dialog.getButton(DialogInterface.BUTTON_POSITIVE).text.toString())
            assertNull("nothing is recorded before Agree", settings.consentedDestination())

            instrumentation.runOnMainSync { dialog.getButton(DialogInterface.BUTTON_POSITIVE).performClick() }
            awaitEnabled(true)

            assertEquals(destination(), settings.consentedDestination())
            assertTrue(accounts.accountExists())
            instrumentation.waitForIdleSync()
            assertTrue(rowBody(scenario), TEST_SYNC_SERVER in rowBody(scenario))
        }
    }

    @Test
    fun declineOrBack_leavesSyncOffAndRecordsNothing() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            instrumentation.waitForIdleSync()
            tapRow(scenario)
            val notNow = awaitDialog(scenario) as androidx.appcompat.app.AlertDialog
            instrumentation.runOnMainSync { notNow.getButton(DialogInterface.BUTTON_NEGATIVE).performClick() }
            instrumentation.waitForIdleSync()

            tapRow(scenario)
            val back = awaitDialog(scenario)
            instrumentation.runOnMainSync { back.cancel() }
            instrumentation.waitForIdleSync()

            assertFalse(settings.isEnabled())
            assertNull(settings.consentedDestination())
            assertFalse(accounts.accountExists())
            // The rest of Settings still works: the row offers sync again.
            assertEquals(context.getString(R.string.settings_contact_sync_off_body), rowBody(scenario))
        }
    }

    @Test
    fun revoke_turnsSyncOffAndForgetsTheConsent() {
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            instrumentation.waitForIdleSync()
            agree(scenario)
            runBlocking { settings.setImportAccounts(destination(), setOf("com.google\nme@example.com")) }

            tapRow(scenario)
            val revoke = awaitDialog(scenario) as androidx.appcompat.app.AlertDialog
            val message = revoke.findViewById<TextView>(android.R.id.message)!!.text.toString()
            assertTrue(message, TEST_SYNC_SERVER in message)
            instrumentation.runOnMainSync { revoke.getButton(DialogInterface.BUTTON_POSITIVE).performClick() }
            awaitEnabled(false)

            assertNull(settings.consentedDestination())
            assertEquals(emptySet<String>(), settings.importAccounts(destination()))
            val deadline = System.currentTimeMillis() + 10_000
            while (accounts.accountExists() && System.currentTimeMillis() < deadline) android.os.SystemClock.sleep(50)
            assertFalse(accounts.accountExists())
            instrumentation.waitForIdleSync()
            assertEquals(context.getString(R.string.settings_contact_sync_off_body), rowBody(scenario))
        }
    }

    /** Sync turned on before the disclosure named the server reads as off until the user agrees. */
    @Test
    fun syncEnabledWithoutConsent_readsAsOff() {
        settings.setEnabled(true)
        assertFalse(settings.isEnabled())
        settings.recordConsent(destination())
        assertTrue(settings.isEnabled())
    }

    /** Unpaired, there is no server to name, so nothing is asked and nothing recorded. */
    @Test
    fun unpaired_asksNothing() {
        unpairAfterSyncTest(context)
        ActivityScenario.launch(SettingsActivity::class.java).use { scenario ->
            instrumentation.waitForIdleSync()
            tapRow(scenario)
            android.os.SystemClock.sleep(1_000)
            instrumentation.waitForIdleSync()
            scenario.onActivity { assertNull(it.contactSyncDialog) }
            assertNull(settings.consentedDestination())
        }
    }
}
