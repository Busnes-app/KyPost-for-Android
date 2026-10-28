package org.kysecurity.mail.security

import android.content.Context
import android.os.SystemClock
import android.view.View
import android.widget.EditText
import androidx.test.core.app.ActivityScenario
import androidx.test.espresso.Espresso.onView
import androidx.test.espresso.action.ViewActions.click
import androidx.test.espresso.action.ViewActions.replaceText
import androidx.test.espresso.action.ViewActions.scrollTo
import androidx.test.espresso.assertion.ViewAssertions.matches
import androidx.test.espresso.matcher.RootMatchers.isDialog
import androidx.test.espresso.matcher.ViewMatchers.isAssignableFrom
import androidx.test.espresso.matcher.ViewMatchers.isChecked
import androidx.test.espresso.matcher.ViewMatchers.isEnabled
import androidx.test.espresso.matcher.ViewMatchers.isDisplayed
import androidx.test.espresso.matcher.ViewMatchers.withText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.runBlocking
import org.hamcrest.Matcher
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.afterSplash
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.mail.MailRuntime

/** Each weakening change raises the PIN prompt, and cancelling it leaves the setting as it was.
 *  No test enters a wrong PIN, so the class never advances the wipe counter. */
@RunWith(AndroidJUnit4::class)
class SecuritySettingsPinConfirmTest {

    private val context: Context get() = InstrumentationRegistry.getInstrumentation().targetContext
    private val graph get() = SecurityRuntime.graph(context)
    private val appLockStore get() = graph.appLockStore

    private lateinit var snapshot: AppLockSnapshot
    private var graceBefore = AppLockSettings.DEFAULT_GRACE_MILLIS

    @Before
    fun enableAndUnlockTheAppLock() = runBlocking {
        snapshot = AppLockSnapshot.capture(context)
        graceBefore = graph.appLockSettings.graceMillis()

        appLockStore.setPin(TEST_PIN.toCharArray())
        appLockStore.resetFailedAttempts()
        appLockStore.enableLock()
        appLockStore.setWipeAfterAttempts(30)
        graph.appLockSettings.setGraceMillis(30_000L)
        assertEquals(UnlockAttemptResult.Success, graph.appLockManager.attemptPin(TEST_PIN.toCharArray()))
        graph.appLockManager.cancelScheduledLock()
    }

    @After
    fun restore() {
        SecuritySettingsActivity.disableLockVerifierForTest = null
        try {
            graph.hostileLocationSettings.setEnabled(false)
            CryptoPolicySettings(context).refuseLegacy = false
            graph.appLockSettings.setGraceMillis(graceBefore)
            graph.biometricUnlockVault.destroy()
        } finally {
            if (::snapshot.isInitialized) snapshot.restore()
            // Graphs the screen built hold the open database; a later wipe test closes it.
            MailRuntime.invalidate()
            ContactsRuntime.invalidate()
            DeviceContactsRuntime.invalidate()
            SecurityRuntime.invalidate()
        }
    }

    @Test
    fun turningTheWipeOffAsksForThePin() = launch {
        awaitThenClick(withText(wipeButtonLabel(30)))
        onView(withText(R.string.security_wipe_threshold_never)).inRoot(isDialog()).perform(click())

        cancelThePinPrompt()
        assertEquals(30, appLockStore.wipeAfterAttempts())
    }

    @Test
    fun turningTheWipeOffWithTheRightPinApplies() = launch {
        awaitThenClick(withText(wipeButtonLabel(30)))
        onView(withText(R.string.security_wipe_threshold_never)).inRoot(isDialog()).perform(click())

        awaitPinPrompt()
        onView(isAssignableFrom(EditText::class.java)).inRoot(isDialog()).perform(replaceText(TEST_PIN))
        onView(withText(R.string.security_set_pin_confirm)).inRoot(isDialog()).perform(click())
        assertTrue("the confirmed change never landed", awaitCondition { appLockStore.wipeAfterAttempts() == null })
    }

    @Test
    fun aLowerWipeThresholdNeedsNoPin() = launch {
        awaitThenClick(withText(wipeButtonLabel(30)))
        onView(withText(attemptsLabel(10))).inRoot(isDialog()).perform(click())

        assertTrue("a strengthening change must apply at once", awaitCondition { appLockStore.wipeAfterAttempts() == 10 })
    }

    @Test
    fun aLongerGraceWindowAsksForThePin() = launch {
        awaitThenClick(withText(context.getString(R.string.security_lock_grace_button, secondsLabel(30))))
        onView(withText(secondsLabel(300))).inRoot(isDialog()).perform(click())

        cancelThePinPrompt()
        assertEquals(30_000L, graph.appLockSettings.graceMillis())
    }

    @Test
    fun turningBiometricUnlockOnAsksForThePin() = launch {
        awaitThenClick(withText(R.string.security_use_biometric_title))

        cancelThePinPrompt()
        assertFalse(appLockStore.isBiometricEnabled())
    }

    @Test
    fun turningHostileLocationProtectionOffAsksForThePin() {
        graph.hostileLocationSettings.setEnabled(true)
        launch {
            awaitThenClick(withText(R.string.security_hostile_location_title))
            onView(withText(R.string.security_hostile_location_confirm_positive)).inRoot(isDialog()).perform(click())

            cancelThePinPrompt()
            assertTrue(graph.hostileLocationSettings.isEnabled())
        }
    }

    @Test
    fun refusingLegacyEncryptionNeedsNoPin() = launch {
        awaitThenClick(withText(R.string.security_refuse_legacy_title))
        assertTrue("a strengthening change must apply at once", awaitCondition { CryptoPolicySettings(context).refuseLegacy })
    }

    @Test
    fun allowingLegacyEncryptionAgainAsksForThePin() {
        CryptoPolicySettings(context).refuseLegacy = true
        launch {
            awaitThenClick(withText(R.string.security_refuse_legacy_title))

            cancelThePinPrompt()
            assertTrue(CryptoPolicySettings(context).refuseLegacy)
        }
    }

    /** The lock switch reads off while its PIN check is pending; the stored lock is still on. */
    @Test
    fun legacyRefusalStaysPinGatedWhileDisablingTheLockIsPending() {
        CryptoPolicySettings(context).refuseLegacy = true
        val started = CompletableDeferred<Unit>()
        val verdict = CompletableDeferred<UnlockAttemptResult>()
        SecuritySettingsActivity.disableLockVerifierForTest = { pin ->
            pin.fill(' ')
            started.complete(Unit)
            verdict.await()
        }
        launch {
            awaitThenClick(withText(R.string.security_require_unlock_title))
            awaitDisplayed { onView(withText(R.string.security_confirm_disable_title)).inRoot(isDialog()) }
            onView(isAssignableFrom(EditText::class.java)).inRoot(isDialog()).perform(replaceText(TEST_PIN))
            onView(withText(R.string.security_set_pin_confirm)).inRoot(isDialog()).perform(click())
            assertTrue("the disable-lock check never started", awaitCondition { started.isCompleted })

            awaitThenClick(withText(R.string.security_refuse_legacy_title))
            assertFalse(
                "legacy refusal was turned off without a PIN while the lock was still on",
                awaitCondition(SETTLE_MS) { !CryptoPolicySettings(context).refuseLegacy },
            )

            verdict.complete(UnlockAttemptResult.Rejected(0L))
            assertTrue("the lock switch was not restored", awaitMatch(withText(R.string.security_require_unlock_title), isChecked()))
            assertTrue("legacy refusal stayed disabled", awaitMatch(withText(R.string.security_refuse_legacy_title), isEnabled()))
            assertTrue(appLockStore.isLockEnabled())
            assertTrue(CryptoPolicySettings(context).refuseLegacy)

            // And once it is resolved, turning it off still asks.
            awaitThenClick(withText(R.string.security_refuse_legacy_title))
            cancelThePinPrompt()
            assertTrue(appLockStore.isLockEnabled())
            assertTrue(CryptoPolicySettings(context).refuseLegacy)
        }
    }

    private fun launch(body: () -> Unit) {
        ActivityScenario.launch(SecuritySettingsActivity::class.java).afterSplash().use { body() }
    }

    private fun awaitPinPrompt() {
        awaitDisplayed { onView(withText(R.string.security_confirm_change_title)).inRoot(isDialog()) }
    }

    private fun cancelThePinPrompt() {
        awaitPinPrompt()
        onView(withText(android.R.string.cancel)).inRoot(isDialog()).perform(click())
        InstrumentationRegistry.getInstrumentation().waitForIdleSync()
    }

    /** The screen builds its views after an off-main read, so the first lookup may come early. */
    private fun awaitThenClick(matcher: Matcher<View>) {
        awaitDisplayed { onView(matcher).perform(scrollTo()) }
        onView(matcher).perform(click())
    }

    private fun awaitDisplayed(find: () -> androidx.test.espresso.ViewInteraction) {
        val deadline = SystemClock.uptimeMillis() + TIMEOUT_MS
        while (true) {
            try {
                find().check(matches(isDisplayed()))
                return
            } catch (e: Throwable) {
                if (SystemClock.uptimeMillis() > deadline) throw e
                SystemClock.sleep(POLL_MS)
            }
        }
    }

    /** State, not visibility: scrolling back to the top-padded first row leaves it clipped. */
    private fun awaitMatch(view: Matcher<View>, state: Matcher<View>) = awaitCondition {
        runCatching { onView(view).check(matches(state)) }.isSuccess
    }

    private fun awaitCondition(timeoutMs: Long = TIMEOUT_MS, condition: () -> Boolean): Boolean {
        val deadline = SystemClock.uptimeMillis() + timeoutMs
        while (SystemClock.uptimeMillis() < deadline) {
            if (condition()) return true
            SystemClock.sleep(POLL_MS)
        }
        return condition()
    }

    private fun attemptsLabel(n: Int) =
        context.resources.getQuantityString(R.plurals.security_wipe_threshold_attempts, n, n)

    private fun wipeButtonLabel(n: Int) = context.getString(R.string.security_wipe_threshold_button, attemptsLabel(n))

    private fun secondsLabel(n: Int) = context.resources.getQuantityString(R.plurals.security_lock_grace_seconds, n, n)

    private companion object {
        const val TEST_PIN = "482913"
        const val TIMEOUT_MS = 10_000L
        const val POLL_MS = 100L
        const val SETTLE_MS = 2_000L
    }
}
