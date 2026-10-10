package org.kysecurity.mail.contacts.device

import android.Manifest
import android.accounts.AccountAuthenticatorResponse
import android.accounts.AccountManager
import android.content.Intent
import android.content.DialogInterface
import android.os.Binder
import android.os.Parcel
import android.provider.ContactsContract
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.kysecurity.mail.contacts.ContactsListActivity
import org.kysecurity.mail.contacts.ContactsRuntime
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/** An "Add account" request, from Settings or any app that asks AccountManager, never turns device
 *  sync on by itself: even with contacts permission already granted, nothing reaches the shared
 *  contacts provider until the user confirms on screen. */
@RunWith(AndroidJUnit4::class)
class AccountSetupConsentTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val settings = DeviceContactSyncSettings(context)
    private val accounts = DeviceContactAccountManager(context)

    @Before
    fun setUp() {
        val automation = InstrumentationRegistry.getInstrumentation().uiAutomation
        automation.grantRuntimePermission(context.packageName, Manifest.permission.READ_CONTACTS)
        automation.grantRuntimePermission(context.packageName, Manifest.permission.WRITE_CONTACTS)
        settings.setEnabled(false)
        accounts.removeAccountBlocking()
    }

    @After
    fun tearDown() {
        PendingAccountSetup.cancel()
        settings.setEnabled(false)
        DeviceContactSyncScheduler.cancelPeriodic(context)
        DeviceContactPurge.deleteSyncedRows(context)
        accounts.removeAccountBlocking()
        DeviceContactsRuntime.invalidate()
        ContactsRuntime.invalidate()
    }

    private fun ownRawContacts(): Int = context.contentResolver.query(
        ContactsContract.RawContacts.CONTENT_URI,
        arrayOf(ContactsContract.RawContacts._ID),
        "${ContactsContract.RawContacts.ACCOUNT_TYPE} = ?",
        arrayOf(DeviceContactAccount.ACCOUNT_TYPE),
        null,
    )?.use { it.count } ?: 0

    @Test
    fun setupWaitsForAnExplicitEnable() {
        val added = CountDownLatch(1)
        PendingAccountSetup.hold(onAdded = { added.countDown() }, onCancelled = {})
        val intent = Intent(context, ContactsListActivity::class.java)
            .putExtra(ContactsListActivity.EXTRA_ACCOUNT_SETUP, true)

        ActivityScenario.launch<ContactsListActivity>(intent).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()

            assertFalse("setup must not answer before the user confirms", added.await(3, TimeUnit.SECONDS))
            assertFalse(settings.isEnabled())
            assertFalse(accounts.accountExists())
            assertEquals(0, ownRawContacts())

            scenario.onActivity { activity ->
                val dialog = activity.setupDialog
                assertNotNull("setup must ask before enabling", dialog)
                dialog!!.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
            }

            assertTrue("confirming answers the request with the account", added.await(15, TimeUnit.SECONDS))
            assertTrue(settings.isEnabled())
            assertTrue(accounts.accountExists())
        }
    }

    /** Sync switched on but the account removed in Settings: setup must not report an account
     *  that does not exist. */
    @Test
    fun setupAnswersOnlyOnceTheAccountExists() {
        settings.setEnabled(true)
        var existedWhenAnswered: Boolean? = null
        val added = CountDownLatch(1)
        PendingAccountSetup.hold(onAdded = { existedWhenAnswered = accounts.accountExists(); added.countDown() }, onCancelled = {})
        val intent = Intent(context, ContactsListActivity::class.java)
            .putExtra(ContactsListActivity.EXTRA_ACCOUNT_SETUP, true)

        ActivityScenario.launch<ContactsListActivity>(intent).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity -> activity.setupDialog?.getButton(DialogInterface.BUTTON_POSITIVE)?.performClick() }

            assertTrue(added.await(15, TimeUnit.SECONDS))
            assertEquals(true, existedWhenAnswered)
        }
    }

    /** A recreated screen (rotation, or the startup check's recreate) picks setup up again. */
    @Test
    fun setupSurvivesRecreation() {
        val added = CountDownLatch(1)
        PendingAccountSetup.hold(onAdded = { added.countDown() }, onCancelled = {})
        val intent = Intent(context, ContactsListActivity::class.java)
            .putExtra(ContactsListActivity.EXTRA_ACCOUNT_SETUP, true)

        ActivityScenario.launch<ContactsListActivity>(intent).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.recreate()
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            assertTrue("the request is still waiting", PendingAccountSetup.isPending)

            scenario.onActivity { activity ->
                val dialog = activity.setupDialog
                assertNotNull("the recreated screen asks again", dialog)
                dialog!!.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
            }

            assertTrue(added.await(15, TimeUnit.SECONDS))
        }
    }

    @Test
    fun decliningAnswersTheCallerWithACancel() {
        val cancelled = CountDownLatch(1)
        PendingAccountSetup.hold(onAdded = {}, onCancelled = { cancelled.countDown() })
        val intent = Intent(context, ContactsListActivity::class.java)
            .putExtra(ContactsListActivity.EXTRA_ACCOUNT_SETUP, true)

        ActivityScenario.launch<ContactsListActivity>(intent).use { scenario ->
            InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            scenario.onActivity { activity ->
                activity.setupDialog!!.getButton(DialogInterface.BUTTON_NEGATIVE).performClick()
            }

            assertTrue(cancelled.await(10, TimeUnit.SECONDS))
            assertFalse(settings.isEnabled())
            assertFalse(accounts.accountExists())
        }
    }

    /** Records what the authenticator answers on one AccountManager response. The transaction
     *  codes are IAccountAuthenticatorResponse's, in declaration order: onResult, then
     *  onRequestContinued, then onError. */
    private class RecordingResponse : Binder() {
        val results = AtomicInteger()
        val errors = AtomicInteger()
        val answered = CountDownLatch(1)

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            when (code) {
                FIRST_CALL_TRANSACTION -> results.incrementAndGet()
                FIRST_CALL_TRANSACTION + 2 -> errors.incrementAndGet()
                else -> return true
            }
            answered.countDown()
            return true
        }

        fun asResponse(): AccountAuthenticatorResponse {
            val parcel = Parcel.obtain()
            try {
                parcel.writeStrongBinder(this)
                parcel.setDataPosition(0)
                return AccountAuthenticatorResponse.CREATOR.createFromParcel(parcel)
            } finally {
                parcel.recycle()
            }
        }
    }

    @Suppress("DEPRECATION") // getParcelable(String, Class) needs API 33.
    private fun requestSetup(authenticator: KyPostContactAuthenticator, response: RecordingResponse): Intent =
        authenticator.addAccount(response.asResponse(), DeviceContactAccount.ACCOUNT_TYPE, null, null, null)!!
            .getParcelable(AccountManager.KEY_INTENT)!!

    /** A screen opened for a request a newer one displaced must not cancel the newer one when it
     *  closes: each caller gets exactly one answer, its own. */
    @Test
    fun closingADisplacedSetupScreen_leavesTheNewRequestWaiting() {
        val authenticator = KyPostContactAuthenticator(context)
        val first = RecordingResponse()
        val second = RecordingResponse()
        val instrumentation = InstrumentationRegistry.getInstrumentation()

        lateinit var secondIntent: Intent
        ActivityScenario.launch<ContactsListActivity>(requestSetup(authenticator, first)).use {
            instrumentation.waitForIdleSync()
            secondIntent = requestSetup(authenticator, second)
        }
        instrumentation.waitForIdleSync()

        ActivityScenario.launch<ContactsListActivity>(secondIntent).use { scenario ->
            instrumentation.waitForIdleSync()
            scenario.onActivity { activity ->
                val dialog = activity.setupDialog
                assertNotNull("the newer request is still waiting", dialog)
                dialog!!.getButton(DialogInterface.BUTTON_POSITIVE).performClick()
            }
            assertTrue(second.answered.await(15, TimeUnit.SECONDS))
        }

        assertEquals("the displaced request: one cancel", 1 to 0, first.errors.get() to first.results.get())
        assertEquals("the newer request: one account", 0 to 1, second.errors.get() to second.results.get())
    }
}
