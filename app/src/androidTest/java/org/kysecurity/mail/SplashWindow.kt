package org.kysecurity.mail

import android.app.Activity
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry

/** Returns once the system splash window over a just-launched screen is gone. The splash is not
 *  focusable, so Espresso sees the Activity focused and taps while the splash still covers it;
 *  LockedActivity's overlay protection drops that tap (FLAG_WINDOW_IS_OBSCURED) and the menu or
 *  dialog it should open never appears. Call it on every launch a test taps into. */
internal fun <A : Activity> ActivityScenario<A>.afterSplash(): ActivityScenario<A> {
    val instrumentation = InstrumentationRegistry.getInstrumentation()
    val splash = "Splash Screen ${instrumentation.targetContext.packageName}"
    val deadline = SystemClock.uptimeMillis() + SPLASH_TIMEOUT_MS
    try {
        while (splash in dumpsysInput()) {
            check(SystemClock.uptimeMillis() < deadline) { "$splash still covers the screen" }
            SystemClock.sleep(SPLASH_POLL_MS)
        }
    } catch (e: Throwable) {
        close()
        throw e
    }
    return this
}

private fun dumpsysInput(): String =
    ParcelFileDescriptor.AutoCloseInputStream(
        InstrumentationRegistry.getInstrumentation().uiAutomation.executeShellCommand("dumpsys input"),
    ).bufferedReader().use { it.readText() }

private const val SPLASH_TIMEOUT_MS = 10_000L
private const val SPLASH_POLL_MS = 50L
