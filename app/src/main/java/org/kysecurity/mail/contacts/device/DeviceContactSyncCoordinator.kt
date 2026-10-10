package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean

class DeviceContactSyncCoordinator(
    private val syncAll: suspend () -> List<String>,
    private val enabled: () -> Boolean,
    // Device sync writes into the OS contacts provider, which the in-memory database does not cover.
    private val hostileLocationEnabled: () -> Boolean = { false },
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var debounceJob: kotlinx.coroutines.Job? = null
    private val isSyncing = AtomicBoolean(false)

    /** A request that arrived mid-sync: that sync may already have read past its change. */
    private val rerun = AtomicBoolean(false)

    private fun syncAllowed(): Boolean = enabled() && !hostileLocationEnabled()

    fun syncNowAsync() {
        if (!syncAllowed()) return
        if (isSyncing.getAndSet(true)) {
            rerun.set(true)
            return
        }
        scope.launch { runBoundedSync("syncNow") }
    }

    fun syncWithDebounce() {
        if (!syncAllowed()) return
        debounceJob?.cancel()
        debounceJob = scope.launch {
            delay(3000)
            if (isSyncing.getAndSet(true)) rerun.set(true) else runBoundedSync("debounced")
        }
    }

    // Not runCatching: it catches Throwable and would swallow the timeout's own cancellation.
    // Loops while requests arrived during the pass; isSyncing is released before the check, so a
    // request either sets rerun before it or starts its own pass after it.
    private suspend fun runBoundedSync(trigger: String) {
        do {
            try {
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
            } finally {
                isSyncing.set(false)
            }
        } while (rerun.getAndSet(false) && syncAllowed() && !isSyncing.getAndSet(true))
    }

    private companion object {
        const val TAG = "DeviceContactSync"
        const val SYNC_TIMEOUT_MS = 30_000L
    }
}
