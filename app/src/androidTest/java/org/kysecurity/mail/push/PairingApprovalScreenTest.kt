package org.kysecurity.mail.push

import android.Manifest
import android.os.SystemClock
import android.view.View
import android.widget.TextView
import androidx.lifecycle.ViewModelProvider
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.R
import org.kysecurity.mail.afterSplash
import java.io.File

/**
 * The waiting-for-approval card (KyPost-Server #516) on the real pairing screen: it replaces the
 * screen, shows the code and the server, and Cancel returns to the start and drops the pending
 * secret. The poll goes to a host that does not resolve, so it only backs off; the polling rules
 * themselves are JVM-tested in `DeviceApprovalTest`.
 *
 * With `-e kypostCaptures true` on a `-PallowScreenshots=true` build it also saves screenshots of
 * the card and of the screen after Cancel to the app's external files dir (`captures/`).
 */
@RunWith(AndroidJUnit4::class)
class PairingApprovalScreenTest {

    private val instrumentation = InstrumentationRegistry.getInstrumentation()

    @Before
    fun noPermissionPrompt() {
        // The screen asks for notifications on open; a system dialog over it would hide the card.
        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.TIRAMISU) {
            instrumentation.uiAutomation.grantRuntimePermission(
                instrumentation.targetContext.packageName,
                Manifest.permission.POST_NOTIFICATIONS,
            )
        }
    }

    private fun pending() = NativeRegistrationResult.Pending(
        pairing = PairingData(
            subscriberId = "sub-1",
            serverUrl = "https://mail.example.com",
            registrationUrl = "https://mail.example.com/api/notifications/native/register",
            pairingToken = "tok",
            deviceId = null,
            deviceSecret = null,
            pairedAtEpochMs = 0L,
        ),
        credential = PushRegistrationCredential(token = "fcm-token"),
        deviceId = "dev-pending",
        deviceSecret = "pending-secret",
        approvalCode = "048213",
        expiresAtEpochMs = System.currentTimeMillis() + 5 * 60_000L,
        statusEndpoint = "https://mail.example.com/api/notifications/native/pairing-status",
        pollIntervalSeconds = 3,
        tlsPin = null,
    )

    @Test
    fun theCardShowsTheCodeAndCancelReturnsToTheStart() {
        ActivityScenario.launch(PushPairingActivity::class.java).afterSplash().use { scenario ->
            val pending = pending()
            scenario.onActivity { activity ->
                ViewModelProvider(activity)[PushHomeViewModel::class.java].awaitApproval(pending)
            }
            awaitVisibility(scenario, R.id.pushPairingApprovalPanel, View.VISIBLE)
            scenario.onActivity { activity ->
                assertEquals("048 213", activity.findViewById<TextView>(R.id.pushPairingApprovalCode).text.toString())
                assertEquals(
                    "Server: mail.example.com",
                    activity.findViewById<TextView>(R.id.pushPairingApprovalServer).text.toString(),
                )
                assertEquals(
                    "Approve this device on the KyPost web page that showed the code. Check the code matches.",
                    activity.findViewById<TextView>(R.id.pushPairingApprovalMessage).text.toString(),
                )
                assertEquals(View.GONE, activity.findViewById<View>(R.id.pushPairingMainPanel).visibility)
            }
            capture("approval")

            scenario.onActivity { it.findViewById<View>(R.id.btnCancelApproval).performClick() }
            awaitVisibility(scenario, R.id.pushPairingApprovalPanel, View.GONE)
            scenario.onActivity {
                assertEquals(View.VISIBLE, it.findViewById<View>(R.id.btnScanQr).visibility)
            }
            // The coordinator wipes in its `finally` once the cancelled poll unwinds.
            val deadline = SystemClock.uptimeMillis() + 5_000
            while (pending.deviceSecret != null && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(50)
            assertNull(pending.deviceSecret)
            capture("pairing")
        }
    }

    /** The app lock finishes the pairing screen while the user approves in a browser; the wait
     *  must survive it, and the next screen must show the card and be able to cancel it. */
    @Test
    fun theWaitOutlivesTheScreenAndTheNextScreenCanCancelIt() {
        val pending = pending()
        ActivityScenario.launch(PushPairingActivity::class.java).afterSplash().use { scenario ->
            scenario.onActivity { activity ->
                ViewModelProvider(activity)[PushHomeViewModel::class.java].awaitApproval(pending)
            }
            awaitVisibility(scenario, R.id.pushPairingApprovalPanel, View.VISIBLE)
        }
        assertEquals("closing the screen wiped the pending secret", "pending-secret", pending.deviceSecret)
        ActivityScenario.launch(PushPairingActivity::class.java).afterSplash().use { scenario ->
            awaitVisibility(scenario, R.id.pushPairingApprovalPanel, View.VISIBLE)
            scenario.onActivity { it.findViewById<View>(R.id.btnCancelApproval).performClick() }
            awaitVisibility(scenario, R.id.pushPairingApprovalPanel, View.GONE)
        }
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (pending.deviceSecret != null && SystemClock.uptimeMillis() < deadline) SystemClock.sleep(50)
        assertNull(pending.deviceSecret)
    }

    private fun awaitVisibility(scenario: ActivityScenario<PushPairingActivity>, id: Int, visibility: Int) {
        val deadline = SystemClock.uptimeMillis() + 5_000
        while (true) {
            instrumentation.waitForIdleSync()
            var actual = -1
            scenario.onActivity { actual = it.findViewById<View>(id).visibility }
            if (actual == visibility || SystemClock.uptimeMillis() > deadline) {
                assertEquals(visibility, actual)
                return
            }
            SystemClock.sleep(50)
        }
    }

    private fun capture(view: String) {
        if (InstrumentationRegistry.getArguments().getString("kypostCaptures") != "true") return
        instrumentation.waitForIdleSync()
        SystemClock.sleep(500)
        val bitmap = instrumentation.uiAutomation.takeScreenshot() ?: return
        val dir = File(instrumentation.targetContext.getExternalFilesDir(null), "captures").apply { mkdirs() }
        File(dir, "$view.png").outputStream().use { bitmap.compress(android.graphics.Bitmap.CompressFormat.PNG, 100, it) }
    }
}
