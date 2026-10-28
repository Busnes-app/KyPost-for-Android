package org.kysecurity.mail.security

import android.content.Intent
import android.os.Bundle
import android.view.MotionEvent
import android.view.View
import androidx.activity.enableEdgeToEdge
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.lifecycleScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import org.kysecurity.mail.BuildConfig

/** The one-shot latch behind a startup notice is spent when the dialog is *built*, so a screen
 *  that cannot show one must not ask: the dialog dies with the Activity while the latch stays set
 *  for the rest of the process, and the pref behind it is only cleared by the user tapping OK.
 *  Order matters — [canShow] is checked before the CAS, never after. */
internal fun claimNotice(
    pending: Boolean,
    canShow: Boolean,
    latch: java.util.concurrent.atomic.AtomicBoolean,
): Boolean = pending && canShow && latch.compareAndSet(false, true)

abstract class LockedActivity : AppCompatActivity() {

    protected open val secureWindow: Boolean = true

    /** False for a screen that routes on and finishes itself: the startup notices are one-shot for
     *  the whole process, so such a screen would spend the latch on a dialog nobody ever sees. */
    protected open val showsStartupNotices: Boolean = true

    /** [AppLockManager.isLockedNow], not the flow value: the grace window may have expired. */
    protected fun isLocked(): Boolean = SecurityRuntime.graph(this).appLockManager.isLockedNow()

    protected var redirectedToUnlock: Boolean = false
        private set

    /** Called only when the startup wipe verdict is in, not terminal, and the app is unlocked. */
    protected abstract fun onCreateUnlocked(savedInstanceState: Bundle?)

    /** [onStart], under the same guarantee as [onCreateUnlocked]. The app can lock while this
     *  screen sits in the back stack, and `onCreate` does not run again on the way back. */
    protected open fun onStartUnlocked() = Unit

    final override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // enableEdgeToEdge must precede setContentView for its cutout mode to reach the window.
        enableEdgeToEdge()
        if (secureWindow) {
            window.applySecureFlag()
            // FLAG_SECURE stops capture; this stops another app drawing over the window and
            // harvesting taps meant for us. See [applyOverlayProtection].
            window.applyOverlayProtection()
        }
        if (!passesStartupTripwire()) return
        redirectToUnlockIfLocked()
        if (redirectedToUnlock || isFinishing) return
        // After the redirect, never before it: these consume a process-wide one-shot latch, and a
        // screen bouncing to UnlockActivity takes the dialog down with it while the latch stays set.
        reportCredentialResets()
        reportStrandedDownloads()
        onCreateUnlocked(savedInstanceState)
    }

    /** Debug only: CI taps that silently did nothing have no other trace of whether this was why. */
    override fun dispatchTouchEvent(ev: MotionEvent): Boolean {
        if (BuildConfig.DEBUG && ev.actionMasked == MotionEvent.ACTION_DOWN &&
            ev.flags and MotionEvent.FLAG_WINDOW_IS_OBSCURED != 0
        ) {
            android.util.Log.w("LockedActivity", "Obscured touch at ${ev.x},${ev.y}; overlay protection drops it")
        }
        return super.dispatchTouchEvent(ev)
    }

    /** Blocks until [SecurityWipe.enforceTripwire] has ruled; false means do nothing at all. */
    // getCompleted() below is guarded by the isCompleted check that opens this function.
    @OptIn(ExperimentalCoroutinesApi::class)
    private fun passesStartupTripwire(): Boolean {
        if (!SecurityWipe.startupVerdict.isCompleted) {
            redirectedToUnlock = true
            window.decorView.visibility = View.INVISIBLE
            lifecycleScope.launch {
                SecurityWipe.startupVerdict.await()
                if (!isFinishing && !isDestroyed) recreate()
            }
            return false
        }

        // First screen to observe a startup wipe relaunches; the CAS keeps it to exactly one.
        val verdict = SecurityWipe.startupVerdict.getCompleted()

        // Unreadable Keystore: neither answer is safe, so show nothing. Transient, not terminal.
        // Both durable halves count. The encrypted half used to be missing from this check, so a
        // store that would not open was read as an empty one — silently, one frame before the
        // tripwire turned that into a wipe. It now refuses to open at all, and this is where that
        // refusal has to land. It arrives as a cached boolean from [SecurityWipe.enforceTripwire]
        // rather than a probe here, because opening that store is disk and Keystore work and this
        // runs in `onCreate` on the way into every screen in the app.
        val lockTripwireUnreadable = SecurityWipe.lockStoreUnreadable ||
            runCatching { AppLockStore(this).tripwireState() }.getOrNull() == TripwireState.UNREADABLE
        // Checked here because isEnabled() resolves UNREADABLE to true, hiding it from callers.
        val protectionUnreadable = runCatching { HostileLocationSettings(this).state() }
            .getOrNull() == HostileLocationState.UNREADABLE
        if (lockTripwireUnreadable || protectionUnreadable) {
            redirectedToUnlock = true
            blockOnUnreadableTripwire()
            return false
        }

        // Terminal, and checked before the one-shot below because this state is not one-shot.
        if (verdict is WipeResult.Incomplete && !verdict.willRetry) {
            redirectedToUnlock = true
            blockOnAbandonedWipe(verdict.failedSteps)
            return false
        }

        if (verdict != null && startupWipeHandled.compareAndSet(false, true)) {
            redirectedToUnlock = true
            val message = when (verdict) {
                is WipeResult.Complete -> org.kysecurity.mail.R.string.security_wiped_notice
                is WipeResult.Incomplete -> {
                    android.util.Log.e("LockedActivity", "Startup wipe incomplete: ${verdict.failedSteps}")
                    if (verdict.willRetry) org.kysecurity.mail.R.string.security_wipe_incomplete_notice
                    else org.kysecurity.mail.R.string.security_wipe_incomplete_final_notice
                }
            }
            android.widget.Toast.makeText(
                applicationContext,
                message,
                android.widget.Toast.LENGTH_LONG,
            ).show()
            // Suspending: the graph teardown it runs quiesces a thread pool, which must not happen
            // on the main thread. See [AppRestart.relaunch].
            lifecycleScope.launch { AppRestart.relaunch(this@LockedActivity) }
            return false
        }

        window.decorView.visibility = View.VISIBLE
        return true
    }

    /** True while this screen will still be on-screen to hold a dialog. */
    private fun canShowNotice(): Boolean =
        showsStartupNotices && !redirectedToUnlock && !isFinishing && !isDestroyed

    /** A wipe that finished cleanly can still have left decrypted attachments in shared Downloads,
     *  which the app cannot delete and the user can. Saying so is the whole point: the alternative
     *  is a "your data has been erased" notice that is not true. */
    private fun reportStrandedDownloads() {
        val stranded = SecurityWipe.strandedDownloadsPending(this)
        if (!claimNotice(stranded > 0, canShowNotice(), strandedDownloadsReported)) return
        android.util.Log.e("LockedActivity", "Wipe left $stranded attachment(s) in shared Downloads")
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(org.kysecurity.mail.R.string.security_stranded_downloads_title)
            .setMessage(
                resources.getQuantityString(
                    org.kysecurity.mail.R.plurals.security_stranded_downloads_message,
                    stranded,
                    stranded,
                ),
            )
            .setPositiveButton(android.R.string.ok) { _, _ -> SecurityWipe.acknowledgeStrandedDownloads(this) }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    private fun reportCredentialResets() {
        val reset = credentialResetsPending(this)
        if (!claimNotice(reset.isNotEmpty(), canShowNotice(), credentialResetReported)) return
        android.util.Log.e("LockedActivity", "Encrypted stores were reset: $reset")
        // Losing the database key costs the cached mail, not just a re-establishable credential.
        val message = if (org.kysecurity.mail.data.DATABASE_NAME in reset) {
            org.kysecurity.mail.R.string.security_credential_reset_message_mail_lost
        } else {
            org.kysecurity.mail.R.string.security_credential_reset_message
        }
        androidx.appcompat.app.AlertDialog.Builder(this)
            .setTitle(org.kysecurity.mail.R.string.security_credential_reset_title)
            .setMessage(message)
            .setPositiveButton(android.R.string.ok) { _, _ -> acknowledgeCredentialResets(this) }
            .setCancelable(false)
            .create()
            .showSecurely()
    }

    /** Transient device condition: asks for a restart, unlike [blockOnAbandonedWipe]. */
    private fun blockOnUnreadableTripwire() {
        android.util.Log.e("LockedActivity", "The tripwire key store is unreadable; refusing to open")
        window.decorView.visibility = View.INVISIBLE
        window.decorView.post {
            if (isFinishing || isDestroyed) return@post
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setCancelable(false)
                .setTitle(org.kysecurity.mail.R.string.security_tripwire_unreadable_title)
                .setMessage(org.kysecurity.mail.R.string.security_tripwire_unreadable_message)
                .setPositiveButton(org.kysecurity.mail.R.string.security_wipe_blocked_close) { _, _ ->
                    finishAffinity()
                }
                .create()
                .showSecurely()
        }
    }

    /** Posted because this runs from onCreate, before the window has a token for a dialog. */
    private fun blockOnAbandonedWipe(failedSteps: List<String>) {
        android.util.Log.e("LockedActivity", "Wipe abandoned; blocking the app. Failed steps: $failedSteps")
        window.decorView.visibility = View.INVISIBLE
        window.decorView.post {
            if (isFinishing || isDestroyed) return@post
            androidx.appcompat.app.AlertDialog.Builder(this)
                .setCancelable(false)
                .setTitle(org.kysecurity.mail.R.string.security_wipe_blocked_title)
                .setMessage(
                    getString(org.kysecurity.mail.R.string.security_wipe_incomplete_final_notice) +
                        "\n\n" + getString(org.kysecurity.mail.R.string.security_wipe_blocked_recovery),
                )
                // The escape hatch. This state is terminal and blocks the app on every launch
                // forever, and the only way out is clearing storage or uninstalling — which the
                // dialog neither said nor offered, leaving the user with a dead app and no route.
                .setNeutralButton(org.kysecurity.mail.R.string.security_wipe_blocked_open_settings) { _, _ ->
                    openAppInfo()
                    finishAffinity()
                }
                .setPositiveButton(org.kysecurity.mail.R.string.security_wipe_blocked_close) { _, _ ->
                    finishAffinity()
                }
                .create()
                .showSecurely()
        }
    }

    /** Best-effort: a device with no settings activity for this package leaves the dialog's text
     *  as the instruction, which is why the text says it too rather than relying on the button. */
    private fun openAppInfo() {
        runCatching {
            startActivity(
                Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS)
                    .setData(android.net.Uri.fromParts("package", packageName, null))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        }.onFailure { android.util.Log.e("LockedActivity", "Could not open App info", it) }
    }

    /** The resume-time half of the gate. Final for the same reason [onCreate] is; subclasses
     *  override [onStartUnlocked]. */
    final override fun onStart() {
        super.onStart()
        // Nothing to gate while we are standing down for the tripwire — this instance is about to
        // be recreated or the task is about to be relaunched.
        if (redirectedToUnlock) return
        redirectToUnlockIfLocked()
        if (redirectedToUnlock || isFinishing) return
        onStartUnlocked()
    }

    private fun redirectToUnlockIfLocked() {
        if (redirectedToUnlock || isFinishing || !isLocked()) return
        redirectedToUnlock = true
        startActivity(Intent(this, UnlockActivity::class.java))
        finish()
    }

    private companion object {
        /** One-shot: later screens must not bounce the task again on the same verdict. NOT reset
         *  by [NoticeLatches] — [AppRestart.relaunch] keeps the process, so the verdict this
         *  latched on is still there, and clearing it would relaunch the task again forever. */
        val startupWipeHandled = java.util.concurrent.atomic.AtomicBoolean(false)

        /** Likewise for the credential-reset notice — one dialog per process, not one per screen. */
        val credentialResetReported = java.util.concurrent.atomic.AtomicBoolean(false)

        /** And for the stranded-downloads notice, for the same reason. */
        val strandedDownloadsReported = java.util.concurrent.atomic.AtomicBoolean(false)

        /** Both notices are cleared by the user tapping OK, which is also what clears the pref
         *  behind them. A relaunch between showing and acknowledging used to lose the notice for
         *  the rest of the process while the pref stayed set — so the user was never told their
         *  credentials had been reset. The process survives [AppRestart.relaunch]; these latches
         *  must not.
         *
         *  ponytail: a configuration change while the dialog is up still costs the notice until
         *  the next process start. Upgrade path: release the latch from `onDestroy` when the pref
         *  behind it is still pending. */
        val noticeLatches = object : org.kysecurity.mail.ProcessScopedState {
            override fun resetForNewSession() {
                credentialResetReported.set(false)
                strandedDownloadsReported.set(false)
            }
        }.also { org.kysecurity.mail.ProcessState.register(it) }
    }
}
