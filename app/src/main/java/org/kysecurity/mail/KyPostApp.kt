package org.kysecurity.mail

import android.app.Application
import android.os.Handler
import android.os.Looper
import android.os.SystemClock
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import androidx.lifecycle.ProcessLifecycleOwner
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.push.PushNotificationDispatcher
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.security.AppLockSettings
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.SecurityWipe
import org.kysecurity.mail.security.WipeResult
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/** Re-reads the delivery mode on every foreground and kicks a pull in "App Pull" mode. */
class KyPostApp : Application(), DefaultLifecycleObserver {

    internal val appScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super<Application>.onCreate()
        installStrictModeInDebug()
        PushNotificationDispatcher.ensureChannel(this)

        appScope.launch {
            // Warm the security graph on IO: building it is a Keystore round trip plus a Tink load.
            runCatching { SecurityRuntime.graph(this@KyPostApp) }
                .onFailure { android.util.Log.e("KyPostApp", "Failed to warm the security graph", it) }

            // Encrypted lock state gone while the tripwire says one existed: destroy the local database.
            val verdict = runCatching { SecurityWipe.enforceTripwire(this@KyPostApp) }
                .onFailure { android.util.Log.e("KyPostApp", "Startup tripwire check failed", it) }
                .getOrElse { WipeResult.Incomplete(listOf("startupTripwireCheck")) }
            SecurityWipe.startupVerdict.complete(verdict)
            if (verdict != null) return@launch

            runCatching { DeviceContactsRuntime.graph(this@KyPostApp).bootstrapIfEnabled() }
                .onFailure { android.util.Log.e("KyPostApp", "Failed to bootstrap device contacts", it) }
        }

        ProcessLifecycleOwner.get().lifecycle.addObserver(this)
    }

    override fun onStart(owner: LifecycleOwner) {
        applyLockGrace()

        // Nothing below runs while locked, mid-wipe, or before the verdict: these are credentialed syncs.
        if (SecurityWipe.blockedByAbandonedWipe(this)) return
        // enforceTripwire may be mid-wipe right now, and a sync would write rows behind the deletion.
        if (!SecurityWipe.startupVerdict.isCompleted) return

        if (SecurityRuntime.graph(this).appLockManager.isLockedNow()) return

        runCatching { PushRuntime.graph(this).pullCoordinator.pullNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to pull", it) }
        runCatching { ContactsRuntime.graph(this).coordinator.syncNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to sync contacts (relay)", it) }
        runCatching { DeviceContactsRuntime.graph(this).coordinator.syncNowAsync() }
            .onFailure { android.util.Log.e("KyPostApp", "Failed to sync contacts (device)", it) }
    }

    /** Monotonic. Zero means "foreground, or the grace window is already resolved". */
    private var backgroundedAtElapsedMs: Long = 0L

    /** Fires [AppLockSettings.graceMillis] after the app backgrounds; see [onStop]. */
    private val lockHandler = Handler(Looper.getMainLooper())
    private val engageLock = Runnable {
        backgroundedAtElapsedMs = 0L
        // Resolve the deadline instead of locking unconditionally: foregrounding or a successful
        // unlock may have cancelled it while this already-queued callback was waiting.
        SecurityRuntime.graph(this).appLockManager.isLockedNow()
    }

    /** Locking is deferred by [AppLockSettings.graceMillis] so a file-picker trip cannot lock. */
    override fun onStop(owner: LifecycleOwner) {
        val grace = AppLockSettings(this).graceMillis()
        if (grace <= 0L) {
            lockHandler.removeCallbacks(engageLock)
            SecurityRuntime.graph(this).appLockManager.lockNow()
            backgroundedAtElapsedMs = 0L
            return
        }
        backgroundedAtElapsedMs = SystemClock.elapsedRealtime()
        // The Handler runs on uptimeMillis, which stops in deep sleep; scheduleLock uses elapsedRealtime.
        SecurityRuntime.graph(this).appLockManager.scheduleLock(backgroundedAtElapsedMs + grace)
        lockHandler.removeCallbacks(engageLock)
        lockHandler.postDelayed(engageLock, grace)
    }

    /** Re-checks the elapsed time itself: a Handler callback dies with the process, and Doze delays it. */
    private fun applyLockGrace() {
        lockHandler.removeCallbacks(engageLock)
        val appLockManager = SecurityRuntime.graph(this).appLockManager
        val backgroundedAt = backgroundedAtElapsedMs
        backgroundedAtElapsedMs = 0L
        if (backgroundedAt == 0L) {
            appLockManager.cancelScheduledLock()
            return
        }
        // elapsedRealtime, not wall clock: a wall-clock window is defeated by changing the device
        // date, exactly as AppLockState.lockoutUntilElapsedMs already documents.
        val away = SystemClock.elapsedRealtime() - backgroundedAt
        if (away >= AppLockSettings(this).graceMillis()) {
            appLockManager.lockNow()
        } else {
            appLockManager.cancelScheduledLock()
        }
    }

    /** Debug only, and log-only rather than penaltyDeath.
     *
     *  This app opens Keystore-backed EncryptedSharedPreferences in a dozen places and is careful
     *  to keep every one off the main thread — carefully enough that the comments say so, and not
     *  carefully enough that they all did. A reviewer found the exceptions by reading. This finds
     *  the next one. `penaltyLog`, because a hard failure on a device the user is holding is a
     *  worse outcome than the jank it is reporting. */
    private fun installStrictModeInDebug() {
        if (!BuildConfig.DEBUG) return
        android.os.StrictMode.setThreadPolicy(
            android.os.StrictMode.ThreadPolicy.Builder()
                .detectDiskReads()
                .detectDiskWrites()
                .detectNetwork()
                .penaltyLog()
                .build(),
        )
    }

    /** [level] is load-bearing: TRIM_MEMORY_UI_HIDDEN fires on every picker trip, not real pressure. */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= TRIM_MEMORY_RUNNING_LOW) org.kysecurity.mail.pgp.EnrollmentSession.clear()
    }
}
