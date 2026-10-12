package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull

class DeviceContactSyncCoordinator(
    private val syncAll: suspend () -> List<String>,
    private val enabled: () -> Boolean,
    // Device sync writes into the OS contacts provider, which the in-memory database does not cover.
    private val hostileLocationEnabled: () -> Boolean = { false },
    private val scope: CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
    /** Runs when a request finds a pass already running; tests use it to stall the requester. */
    private val onFoundRunning: () -> Unit = {},
) {
    private var debounceJob: kotlinx.coroutines.Job? = null

    // A request and a pass's decision to stop are decided under one lock, so a request either
    // claims a new pass or is seen by the running one before it stops. Never both, never neither.
    private val lock = Any()
    private var running = false

    /** A request that arrived mid-sync: that sync may already have read past its change. */
    private var rerun = false

    private fun syncAllowed(): Boolean = enabled() && !hostileLocationEnabled()

    /** True when the caller must run a pass; false when the running pass will run once more. */
    private fun claimPass(): Boolean = synchronized(lock) {
        if (running) {
            rerun = true
            false
        } else {
            running = true
            true
        }
    }

    /** After a pass: true to run another for a request that arrived meanwhile, else stop. */
    private fun runAgainOrStop(): Boolean = synchronized(lock) {
        val again = rerun && syncAllowed()
        rerun = false
        if (!again) running = false
        again
    }

    fun syncNowAsync() {
        if (!syncAllowed()) return
        if (claimPass()) scope.launch { runBoundedSync("syncNow") } else onFoundRunning()
    }

    fun syncWithDebounce() {
        if (!syncAllowed()) return
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(3000)
            if (claimPass()) runBoundedSync("debounced")
        }
    }

    private suspend fun runBoundedSync(trigger: String) {
        try {
            do runOnce(trigger) while (runAgainOrStop())
        } catch (e: kotlinx.coroutines.CancellationException) {
            synchronized(lock) {
                running = false
                rerun = false
            }
            throw e
        }
    }

    // Not runCatching: it catches Throwable and would swallow the timeout's own cancellation.
    private suspend fun runOnce(trigger: String) {
        val failedStages = withTimeoutOrNull(SYNC_TIMEOUT_MS) {
            try {
                syncAll()
            } catch (e: kotlinx.coroutines.CancellationException) {
                throw e
            } catch (e: Exception) {
                android.util.Log.e(TAG, "Sync ($trigger) threw before any stage could report", e)
                listOf("syncAll")
            }
        }
        when {
            failedStages == null ->
                android.util.Log.e(TAG, "Sync ($trigger) hit the ${SYNC_TIMEOUT_MS}ms ceiling and was abandoned")
            failedStages.isNotEmpty() ->
                android.util.Log.e(TAG, "Sync ($trigger) stages failed: $failedStages")
        }
    }

    private companion object {
        const val TAG = "DeviceContactSync"
        const val SYNC_TIMEOUT_MS = 30_000L
    }
}
