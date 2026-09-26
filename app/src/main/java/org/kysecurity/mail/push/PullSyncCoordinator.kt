package org.kysecurity.mail.push

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/** Drives App Pull mode and the push-mode heartbeat; the cursor is durable across both.
 *
 *  The server writes every notification to the pull queue in both delivery modes and never flips
 *  the mode itself, so a device on a dead relay recovers only if it polls. In PUSH mode this polls
 *  once the transport has been quiet for [PUSH_QUIET_THRESHOLD_MS]; in PULL mode it always polls. */
class PullSyncCoordinator(
    private val repository: PushStore,
    // No default. A no-arg PullNotificationClient() built the plain unpinned client, which is the
    // same "the security control's default is off" shape the eight clients below it had.
    private val pullClient: PullNotificationClient,
    // The two Android edges, injected rather than reached through a stored Context. Without this
    // the duplicate-notification rule below could only be exercised from an instrumented test,
    // which is exactly where a concurrency bug hides.
    private val notifier: (IncomingPush) -> Unit,
    private val ensurePeriodic: () -> Unit,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** ONE pull at a time, process-wide.
     *
     *  App foreground, the pairing screen and [PullWorker] all enter [pullOnce] independently. The
     *  cursor is read at the start and advanced at the end, so two overlapping runs read the same
     *  cursor and both fetch, persist and NOTIFY the same batch. `appendPayload` dedupes history
     *  by `messageId`; the system notification manager is handed each payload regardless, so the
     *  user simply sees every message twice. */
    private val pullGate = Mutex()

    /** Fire-and-forget pull, used on app foreground and after pairing. */
    fun pullNowAsync() {
        scope.launch { runCatching { pullOnce() } }
    }

    /** Safe to call when unpaired or while push is healthy; reports without touching the network. */
    suspend fun pullOnce(): PullOutcome = pullGate.withLock { pullLocked() }

    private suspend fun pullLocked(): PullOutcome {
        val state = repository.state.first()
        val pairing = repository.pairingForAuthenticatedCall() ?: return PullOutcome.NotPaired
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return PullOutcome.NotPaired

        // Armed in both modes: the worker is the heartbeat, and pullOnce decides whether to poll.
        ensurePeriodic()
        val now = clock()
        val heartbeat = state.deliveryMode == DeliveryMode.PUSH
        if (heartbeat && now - pushQuietSince(state) < PUSH_QUIET_THRESHOLD_MS) return PullOutcome.PushHealthy

        val endpoint = resolvePullEndpoint(pairing.serverUrl, state.pullEndpoint)
        if (endpoint.isBlank()) return PullOutcome.Failed("Server URL is not valid")
        val cursor = repository.pullCursor(pairing.subscriberId)

        return when (val result = pullClient.pull(
            pullEndpoint = endpoint,
            deviceId = deviceId,
            deviceSecret = deviceSecret,
            afterCursor = cursor,
        )) {
            is PullResult.Success -> handleSuccess(
                subscriberId = pairing.subscriberId,
                endpoint = endpoint,
                cursor = cursor,
                response = result.response,
                now = now,
                // A heartbeat's cursor can be months stale; everything push already delivered in
                // that time would otherwise come back as up to 100 notifications at once. History
                // dedupes only the last few, so age is the bound. Twice the threshold: the first
                // heartbeat runs one period after the threshold, and nothing since the last push
                // may be dropped.
                minCreatedAtEpochMs = if (heartbeat) now - 2 * PUSH_QUIET_THRESHOLD_MS else 0L,
            )
            is PullResult.Unauthorized -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Unauthorized
            }
            is PullResult.BadRequest -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Failed(result.message)
            }
            is PullResult.Retryable -> {
                repository.updateSyncState(lastSyncAtEpochMs = null, syncError = result.message)
                PullOutcome.Retry(result.retryAfterSeconds)
            }
        }
    }

    /** A device that has never seen a push counts from its registration: that is the last moment
     *  the relay was proven reachable, and it gives a fresh token the threshold to deliver. */
    private fun pushQuietSince(state: PushState): Long =
        state.lastPushReceivedAtEpochMs ?: state.lastTokenSyncAtEpochMs ?: 0L

    private suspend fun handleSuccess(
        subscriberId: String,
        endpoint: String,
        cursor: Long,
        response: PullNotificationsResponse,
        now: Long,
        minCreatedAtEpochMs: Long,
    ): PullOutcome {
        // The response mode is authoritative: a flip to PULL makes the next tick poll unconditionally.
        repository.updateDelivery(response.mode, endpoint)

        val prepared = PullNotificationProcessor.prepare(
            response,
            currentCursor = cursor,
            nowEpochMs = now,
            minCreatedAtEpochMs = minCreatedAtEpochMs,
        )
        for (incoming in prepared.incoming) {
            // Persist to in-app history AND hand off to the system notification manager
            // BEFORE advancing the cursor, so a crash mid-batch re-fetches rather than drops.
            // History is the dedupe against what push already delivered: same messageId, no re-alert.
            if (incoming is IncomingPush.Mail && !repository.appendPayload(incoming.payload)) continue
            notifier(incoming)
        }
        repository.advancePullCursor(subscriberId, prepared.nextCursor)
        repository.updateSyncState(lastSyncAtEpochMs = now, syncError = null)
        return PullOutcome.Pulled(prepared.incoming.size)
    }

    companion object {
        /** How long the push transport may be silent before the periodic worker polls instead.
         *  A constant, not a setting: the cost of guessing wrong is one 15-minute tick's latency. */
        const val PUSH_QUIET_THRESHOLD_MS = 3 * 60 * 60 * 1000L
    }
}

/** Result of a pull cycle, primarily to let [PullWorker] decide retry vs. success. */
sealed class PullOutcome {
    data class Pulled(val count: Int) : PullOutcome()
    object NotPaired : PullOutcome()
    /** PUSH mode and a push arrived within the threshold; nothing was fetched. */
    object PushHealthy : PullOutcome()
    object Unauthorized : PullOutcome()
    data class Failed(val message: String) : PullOutcome()
    data class Retry(val retryAfterSeconds: Long?) : PullOutcome()
}
