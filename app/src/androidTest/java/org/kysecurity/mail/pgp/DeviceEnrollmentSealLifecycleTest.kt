package org.kysecurity.mail.pgp

import android.content.Intent
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
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
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The seal prompt before authentication: destruction cancels, and the previous record is kept. */
@RunWith(AndroidJUnit4::class)
class DeviceEnrollmentSealLifecycleTest {

    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val vault = EnrollmentVault(context)

    @Before
    fun prepareStoredVault() {
        EnrollmentSession.clear()
        vault.destroy()
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        assertTrue(vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 }))
    }

    @After
    fun cleanup() {
        EnrollmentSession.clear()
        vault.destroy()
    }

    @Test
    fun recreatingWhileTheSealPromptIsOpenCancelsAndKeepsThePreviousRecord() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
        val outcome = AtomicReference<SealOutcome>()
        val completed = CountDownLatch(1)
        val intent = Intent(context, DeviceEnrollmentActivity::class.java)

        try {
            ActivityScenario.launch<DeviceEnrollmentActivity>(intent).use { scenario ->
                scenario.onActivity { activity ->
                    scope.launch(start = CoroutineStart.UNDISPATCHED) {
                        outcome.set(activity.sealForTest(ByteArray(64) { 3 }))
                        completed.countDown()
                    }
                }

                awaitCondition("the seal prompt was never displayed") {
                    val root = InstrumentationRegistry.getInstrumentation().uiAutomation.rootInActiveWindow
                    root?.packageName == "com.android.systemui" &&
                        root.findAccessibilityNodeInfosByText(context.getString(R.string.enrollment_auth_title))
                            .any { it.isVisibleToUser }
                }

                scenario.recreate()

                assertTrue("the destroyed Activity stranded its seal", completed.await(5, TimeUnit.SECONDS))
                assertTrue("expected Cancelled, got ${outcome.get()}", outcome.get() is SealOutcome.Cancelled)
                awaitCondition("the cancelled prompt still owns window focus") {
                    var focused = false
                    scenario.onActivity { focused = it.hasWindowFocus() }
                    focused
                }
                InstrumentationRegistry.getInstrumentation().waitForIdleSync()
            }
        } finally {
            scope.cancel()
        }

        val (iv, ciphertext) = EnrollmentVault(context).stored()!!
        assertArrayEquals(ByteArray(12) { 7 }, iv)
        assertArrayEquals(ByteArray(48) { 9 }, ciphertext)
        assertFalse(File(context.filesDir, "${EnrollmentVault.RECORD_FILE}.new").exists())
        assertFalse(EnrollmentSession.isHeld())
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
