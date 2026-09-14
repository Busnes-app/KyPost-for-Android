package org.kysecurity.mail.pgp

import android.content.Intent
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.kysecurity.mail.R
import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotSame
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class DeviceEnrollmentOpenLifecycleTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val vault = EnrollmentVault(context)

    @Before
    fun prepareStoredVault() {
        EnrollmentSession.clear()
        vault.destroy()
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 })
    }

    @After
    fun cleanup() {
        EnrollmentSession.clear()
        vault.destroy()
    }

    @Test
    fun recreatingWhileTheOldVaultPromptIsOpenCompletesAsCancelled() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        val outcome = AtomicReference<OpenOutcome>()
        val completed = CountDownLatch(1)
        val oldActivity = AtomicReference<DeviceEnrollmentActivity>()
        val intent = Intent(context, DeviceEnrollmentActivity::class.java)

        try {
            ActivityScenario.launch<DeviceEnrollmentActivity>(intent).use { scenario ->
                scenario.onActivity { activity ->
                    oldActivity.set(activity)
                    scope.launch(start = CoroutineStart.UNDISPATCHED) {
                        outcome.set(activity.openPreviousVaultForTest())
                        completed.countDown()
                    }
                }

                // liveOpen only means authenticate() was requested. Recreating before SystemUI
                // attaches its window hits Android 12's pre-attachment dismissal race.
                awaitCondition("the vault-open prompt was never displayed") {
                    val root = InstrumentationRegistry.getInstrumentation().uiAutomation.rootInActiveWindow
                    root?.packageName == "com.android.systemui" &&
                        root.findAccessibilityNodeInfosByText(context.getString(R.string.email_pgp_unlock_title))
                            .any { it.isVisibleToUser }
                }
                scenario.onActivity { assertTrue(it.hasPendingVaultPromptForTest()) }

                scenario.recreate()

                assertTrue("the destroyed Activity stranded its open", completed.await(5, TimeUnit.SECONDS))
                assertTrue(outcome.get() is OpenOutcome.Cancelled)
                scenario.onActivity { replacement -> assertNotSame(oldActivity.get(), replacement) }
                awaitCondition("the cancelled prompt still owns window focus") {
                    var focused = false
                    scenario.onActivity { focused = it.hasWindowFocus() }
                    focused
                }
                InstrumentationRegistry.getInstrumentation().waitForIdleSync()
                assertFalse("a late old-Activity callback repopulated the session", EnrollmentSession.isHeld())
            }
        } finally {
            scope.cancel()
        }
    }

    private fun awaitCondition(message: String, condition: () -> Boolean) {
        val deadline = SystemClock.elapsedRealtime() + 5_000L
        while (SystemClock.elapsedRealtime() < deadline) {
            if (condition()) return
            SystemClock.sleep(50L)
        }
        throw AssertionError(message)
    }
}
