package org.kysecurity.mail

import android.os.SystemClock
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario

/** ActivityScenario.close() relaunches androidx.test's EmptyActivity and waits 45s for a resume that
 *  never comes when one is already on top. A for-result launch has one there whenever the finished
 *  screen is not yet destroyed, so wait for that first. A test left in CREATED has the same problem;
 *  it moves back to RESUMED instead. */
internal fun ActivityScenario<*>.awaitDestroyed() {
    // Past the framework's 10s idle timeout for destroying a finished activity; close() still follows.
    val deadline = SystemClock.uptimeMillis() + 15_000L
    while (runCatching { state }.getOrNull() != Lifecycle.State.DESTROYED && SystemClock.uptimeMillis() < deadline) {
        SystemClock.sleep(50)
    }
}
