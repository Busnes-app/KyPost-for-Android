// androidx.security-crypto is deprecated with no replacement; AppLockSnapshot mirrors AppLockStore.
@file:Suppress("DEPRECATION")

package org.kysecurity.mail.security

import android.app.Activity
import android.app.Application
import android.app.Instrumentation
import android.content.Context
import android.content.Intent
import android.os.Bundle
import android.os.SystemClock
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.google.android.material.navigation.NavigationBarView
import androidx.test.platform.app.InstrumentationRegistry
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.EmailDetailActivity
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.R
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.mail.MailRuntime

/** Never let this class reach LockoutPolicy.WIPE_THRESHOLD: at most one PIN attempt per test. */
@RunWith(AndroidJUnit4::class)
class FoldLockBehaviourTest {

    private val instrumentation: Instrumentation get() = InstrumentationRegistry.getInstrumentation()
    private val context: Context get() = instrumentation.targetContext
    private val application: Application get() = context.applicationContext as Application

    private val graph get() = SecurityRuntime.graph(context)
    private val appLockManager get() = graph.appLockManager

    /** The graph's own store, not a fresh [AppLockStore]: reading it through the graph is what
     *  guarantees the graph — and therefore the [AppLockManager] whose `_locked` is seeded from
     *  `isLockEnabled()` at construction — already exists before the lock is switched on. */
    private val appLockStore get() = graph.appLockStore

    private lateinit var snapshot: AppLockSnapshot
    private lateinit var activities: ActivityTracker

    @Before
    fun enableTheAppLock() = runBlocking {
        // Before the first write below, and before anything can throw: this is the only record of
        // what has to be handed back.
        snapshot = AppLockSnapshot.capture(context)
        activities = ActivityTracker()
        application.registerActivityLifecycleCallbacks(activities)

        appLockStore.setPin(TEST_PIN.toCharArray())
        // Before the one attempt below, so a lockout left armed by an earlier class cannot turn it
        // into a Rejected — which is the only shape in which this class could ever contribute to
        // the wipe counter at all.
        appLockStore.resetFailedAttempts()
        appLockStore.enableLock()
        // Enabled but NOT engaged. attemptPin is the only supported way to clear the locked flag
        // without a biometric CryptoObject, and it is what makes the resize test a real assertion
        // rather than a tautology — the lock is armed, and the recreate must still not trip it.
        assertEquals(
            "Setup failed: the app lock could not be brought to enabled-and-unlocked.",
            UnlockAttemptResult.Success,
            appLockManager.attemptPin(TEST_PIN.toCharArray()),
        )
        // A background grace window armed by an earlier test class would expire mid-test and lock
        // the app for reasons that have nothing to do with folding.
        appLockManager.cancelScheduledLock()
        assertFalse(appLockManager.isLockedNow())
    }

    /** DataRuntime is deliberately NOT invalidated: it owns the open DB and would orphan a handle. */
    @After
    fun restoreTheAppLockStateAsFound() {
        try {
            // isInitialized, because JUnit runs this even when the setup above threw part-way —
            // and a teardown that dies on an uninitialised field reports itself instead of the
            // failure that caused it, while leaving every restore below undone.
            if (::activities.isInitialized) {
                try {
                    finishEveryActivityStartedHere()
                } finally {
                    application.unregisterActivityLifecycleCallbacks(activities)
                }
            }
        } finally {
            if (::snapshot.isInitialized) snapshot.restore()
            MailRuntime.invalidate()
            ContactsRuntime.invalidate()
            DeviceContactsRuntime.invalidate()
            SecurityRuntime.invalidate()
        }
    }

    @Test
    fun aLiveResizeDoesNotEngageTheAppLock() {
        assertTrue(
            "Vacuous unless the lock is armed — lockNow() is a no-op with the lock disabled.",
            appLockStore.isLockEnabled(),
        )

        val inbox = startPane(InboxActivity::class.java)
        val recreated = awaitCreated(InboxActivity::class.java) {
            instrumentation.runOnMainSync { inbox.recreate() }
        }
        assertNotNull("The inbox was never recreated, so nothing was asserted.", recreated)

        assertFalse(
            "A configuration-change recreate must not lock the app — every unfold would prompt for a PIN.",
            appLockManager.isLockedNow(),
        )
    }

    @Test
    fun lockNowStillGatesTheInbox() {
        val inbox = startPane(InboxActivity::class.java)

        appLockManager.lockNow()

        // Both monitors are registered before the trigger: the redirect happens synchronously
        // inside the recreated Activity's onCreate, so a monitor added afterwards would miss it.
        val inboxMonitor = instrumentation.addMonitor(InboxActivity::class.java.name, null, false)
        val unlockMonitor = instrumentation.addMonitor(UnlockActivity::class.java.name, null, false)
        try {
            instrumentation.runOnMainSync { inbox.recreate() }

            val recreated = inboxMonitor.waitForActivityWithTimeout(LAUNCH_TIMEOUT_MS)
            assertNotNull("The inbox was never recreated, so nothing was asserted.", recreated)
            assertNotNull(
                "A locked app must send the gated screen to the unlock prompt.",
                unlockMonitor.waitForActivityWithTimeout(LAUNCH_TIMEOUT_MS),
            )
            assertTrue(
                "A locked app must finish a gated screen rather than leave it under the prompt.",
                awaitFinished(recreated),
            )
        } finally {
            instrumentation.removeMonitor(inboxMonitor)
            instrumentation.removeMonitor(unlockMonitor)
        }
    }

    /** The emulator has no real split, so the primary is re-started (onStart gate), not recreated. */
    @Test
    fun lockingTwoEmbeddedPanesProducesExactlyOneUnlockPrompt() {
        val primary = startPane(InboxActivity::class.java)
        val secondary = startPaneFrom(primary, EmailDetailActivity::class.java) {
            putExtra("email_id", "test-message-1")
            putExtra("email_folder", "INBOX")
        }
        assertEquals(
            "Precondition: an unlock prompt left alive by earlier work would absorb both " +
                "redirects and make the count below meaningless.",
            0,
            activities.unlockPromptsCreated.get(),
        )

        appLockManager.lockNow()

        val gatedSecondary = awaitCreated(EmailDetailActivity::class.java) {
            instrumentation.runOnMainSync { secondary.recreate() }
        }
        assertNotNull("The secondary pane was never recreated, so nothing was asserted.", gatedSecondary)
        assertTrue(
            "The secondary pane must not survive a lock underneath its own prompt.",
            awaitFinished(gatedSecondary),
        )

        // singleTop, and it is the top of its own task by now, so this normally reaches the live
        // instance as onNewIntent + onStart and no second instance is created. Whichever instance
        // the system routes to is the one that ran the gate, and it is the one asserted on.
        val gatedPrimary = awaitCreated(InboxActivity::class.java, NO_NEW_INSTANCE_TIMEOUT_MS) {
            context.startActivity(
                Intent(context, InboxActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
            )
        } ?: primary
        assertTrue(
            "The primary pane must not survive a lock underneath its own prompt.",
            awaitFinished(gatedPrimary),
        )

        assertEquals(
            "Two embedded panes locking at once must collapse into ONE unlock " +
                "prompt via UnlockActivity's singleInstance launch mode, not stack two.",
            1,
            activities.unlockPromptsCreated.get(),
        )
    }

    /** In a split the message rail holds the only Lock (the inbox hides its own navigation), so
     *  the prompt must cover the window: in the message pane it left the inbox list beside it
     *  readable and usable, because a visible screen only checks the lock when it starts. */
    @Test
    fun lockFromTheSplitRailCoversTheInboxPane() {
        assumeTrue(
            "Needs a window that splits (splitMinWidthDp is 840).",
            context.resources.configuration.screenWidthDp >= 840,
        )
        val primary = startPane(InboxActivity::class.java)
        val secondary = startPaneFrom(primary, EmailDetailActivity::class.java) {
            putExtra("email_preview", "body")
        }
        val rail = secondary.findViewById<NavigationBarView>(R.id.detailRail)
        assertTrue("Precondition: the message rail shows in the split.", awaitOnMain { rail.isShown })

        val unlock = awaitCreated(UnlockActivity::class.java) {
            instrumentation.runOnMainSync { rail.selectedItemId = R.id.nav_lock }
        }
        assertNotNull("Lock on the rail never opened the unlock prompt.", unlock)
        assertTrue("The unlock prompt never reached RESUMED.", awaitResumed(unlock!!))
        assertTrue(
            "The inbox pane must not stay visible beside the unlock prompt.",
            awaitOnMain { !activities.isStarted(primary) },
        )
        assertTrue("Lock on the message rail must close the message.", awaitFinished(secondary))
    }

    /** Starts [cls] in its own task and waits for it to reach `RESUMED`. Only for the unlocked
     *  set-up launches: a gated screen never gets there, which is what [awaitCreated] is for. */
    private fun <T : Activity> startPane(cls: Class<T>, configure: Intent.() -> Unit = {}): T =
        awaitResumedPane(cls) {
            context.startActivity(
                Intent(context, cls).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK).apply(configure),
            )
        }

    /** As [startPane], but started *from* [parent] so the two panes share one task — which is what
     *  makes them a split rather than two unrelated screens. */
    private fun <T : Activity> startPaneFrom(
        parent: Activity,
        cls: Class<T>,
        configure: Intent.() -> Unit = {},
    ): T = awaitResumedPane(cls) {
        val intent = Intent(context, cls).apply(configure)
        instrumentation.runOnMainSync { parent.startActivity(intent) }
    }

    private fun <T : Activity> awaitResumedPane(cls: Class<T>, start: () -> Unit): T {
        val activity = awaitCreated(cls, trigger = start)
        assertNotNull("${cls.simpleName} never started.", activity)
        assertTrue("${cls.simpleName} never reached RESUMED.", awaitResumed(activity!!))
        return activity
    }

    /** The monitor goes up first: a gated screen redirects and finishes from inside onCreate. */
    @Suppress("UNCHECKED_CAST")
    private fun <T : Activity> awaitCreated(
        cls: Class<T>,
        timeoutMs: Long = LAUNCH_TIMEOUT_MS,
        trigger: () -> Unit,
    ): T? {
        val monitor = instrumentation.addMonitor(cls.name, null, false)
        return try {
            trigger()
            val activity = monitor.waitForActivityWithTimeout(timeoutMs) as T?
            instrumentation.waitForIdleSync()
            activity
        } finally {
            instrumentation.removeMonitor(monitor)
        }
    }

    /** `finish()` is asynchronous, so reading the flag once races the redirect that set it. */
    private fun awaitFinished(activity: Activity?): Boolean {
        if (activity == null) return false
        return awaitOnMain { activity.isFinishing || activity.isDestroyed }
    }

    private fun awaitResumed(activity: Activity): Boolean = awaitOnMain { activities.isResumed(activity) }

    private fun awaitOnMain(condition: () -> Boolean): Boolean {
        val deadline = SystemClock.uptimeMillis() + SETTLE_TIMEOUT_MS
        while (true) {
            var satisfied = false
            instrumentation.runOnMainSync { satisfied = condition() }
            if (satisfied) return true
            if (SystemClock.uptimeMillis() >= deadline) return false
            Thread.sleep(POLL_INTERVAL_MS)
        }
    }

    /** Loops rather than sweeping once: finishing a gated pane can start another UnlockActivity. */
    private fun finishEveryActivityStartedHere() {
        val deadline = SystemClock.uptimeMillis() + SETTLE_TIMEOUT_MS
        while (true) {
            val live = activities.live()
            if (live.isEmpty()) break
            instrumentation.runOnMainSync { live.forEach { if (!it.isFinishing) it.finish() } }
            if (SystemClock.uptimeMillis() >= deadline) break
            Thread.sleep(POLL_INTERVAL_MS)
        }
        instrumentation.waitForIdleSync()
    }

    /** A second UnlockActivity onCreate is exactly "the system stacked a second prompt". */
    private class ActivityTracker : Application.ActivityLifecycleCallbacks {
        private val liveActivities = Collections.synchronizedList(mutableListOf<Activity>())
        private val resumedActivities = Collections.synchronizedList(mutableListOf<Activity>())
        private val startedActivities = Collections.synchronizedList(mutableListOf<Activity>())
        val unlockPromptsCreated = AtomicInteger(0)

        fun live(): List<Activity> = synchronized(liveActivities) { liveActivities.toList() }
        fun isResumed(activity: Activity): Boolean =
            synchronized(resumedActivities) { resumedActivities.contains(activity) }
        fun isStarted(activity: Activity): Boolean =
            synchronized(startedActivities) { startedActivities.contains(activity) }

        override fun onActivityCreated(activity: Activity, savedInstanceState: Bundle?) {
            if (activity is UnlockActivity) unlockPromptsCreated.incrementAndGet()
            synchronized(liveActivities) { liveActivities.add(activity) }
        }

        override fun onActivityResumed(activity: Activity) {
            synchronized(resumedActivities) { resumedActivities.add(activity) }
        }

        override fun onActivityPaused(activity: Activity) {
            synchronized(resumedActivities) { resumedActivities.remove(activity) }
        }

        override fun onActivityDestroyed(activity: Activity) {
            synchronized(liveActivities) { liveActivities.remove(activity) }
            synchronized(resumedActivities) { resumedActivities.remove(activity) }
            synchronized(startedActivities) { startedActivities.remove(activity) }
        }

        override fun onActivityStarted(activity: Activity) {
            synchronized(startedActivities) { startedActivities.add(activity) }
        }

        override fun onActivityStopped(activity: Activity) {
            synchronized(startedActivities) { startedActivities.remove(activity) }
        }
        override fun onActivitySaveInstanceState(activity: Activity, outState: Bundle) = Unit
    }

    private companion object {
        const val TEST_PIN = "482913"
        const val LAUNCH_TIMEOUT_MS = 15_000L
        const val SETTLE_TIMEOUT_MS = 10_000L

        /** Short on purpose: the expected outcome of restarting a `singleTop` Activity that is
         *  already the top of its task is that no new instance appears at all, and this is how long
         *  the test waits to be sure of it. */
        const val NO_NEW_INSTANCE_TIMEOUT_MS = 3_000L
        const val POLL_INTERVAL_MS = 50L
    }
}

/** Write the tripwire file AFTER the encrypted one, or the teardown arms SecurityWipe. */
internal class AppLockSnapshot(
    private val context: Context,
    private val secure: Map<String, Any?>,
    private val tripwire: Map<String, Any?>,
) {

    fun restore() {
        write(securePrefs(context), secure)
        write(context.getSharedPreferences(TRIPWIRE_FILE, Context.MODE_PRIVATE), tripwire)
    }

    private fun write(prefs: android.content.SharedPreferences, values: Map<String, Any?>) {
        val editor = prefs.edit().clear()
        values.forEach { (key, value) ->
            when (value) {
                is Boolean -> editor.putBoolean(key, value)
                is Int -> editor.putInt(key, value)
                is Long -> editor.putLong(key, value)
                is Float -> editor.putFloat(key, value)
                is String -> editor.putString(key, value)
                // Loud rather than silent: an unrestored key is app-lock state this class ate.
                else -> error("Cannot restore app-lock preference '$key' of type ${value?.javaClass}")
            }
        }
        editor.commit()
    }

    companion object {
        /** Must match [AppLockStore]'s own file names and key scheme, or this reads and writes a
         *  different file than the one under test. */
        private const val SECURE_FILE = "app_lock_secure"
        private const val TRIPWIRE_FILE = "app_lock_tripwire"

        fun capture(context: Context): AppLockSnapshot {
            val appContext = context.applicationContext
            return AppLockSnapshot(
                context = appContext,
                secure = securePrefs(appContext).all.toMap(),
                tripwire = appContext.getSharedPreferences(TRIPWIRE_FILE, Context.MODE_PRIVATE).all.toMap(),
            )
        }

        private fun securePrefs(context: Context): android.content.SharedPreferences {
            val masterKey = MasterKey.Builder(context.applicationContext)
                .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
                .build()
            return EncryptedSharedPreferences.create(
                context.applicationContext,
                SECURE_FILE,
                masterKey,
                EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
                EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM,
            )
        }
    }
}
