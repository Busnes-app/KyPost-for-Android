package org.kysecurity.mail.push

import android.app.Activity
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class PushHomeViewModel(application: Application) : AndroidViewModel(application) {
    private val graph = PushRuntime.graph(application)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val isWorking = MutableStateFlow(false)
    private val localMessage = MutableStateFlow<String?>(null)

    /** One element per registration that succeeded; conflated, so a stopped screen still gets it. */
    private val pairedChannel = Channel<Unit>(Channel.CONFLATED)
    val paired: Flow<Unit> = pairedChannel.receiveAsFlow()

    val uiState: StateFlow<PushHomeUiState> = combine(
        graph.repository.state,
        isWorking,
        localMessage,
    ) { repo, working, local ->
        PushHomeUiState(
            pairing = repo.pairing,
            lastTokenSyncAtEpochMs = repo.lastTokenSyncAtEpochMs,
            syncError = repo.syncError,
            latestPayload = repo.latestPayload,
            history = repo.history,
            deliveryMode = repo.deliveryMode,
            transport = repo.transport,
            isWorking = working,
            localMessage = local,
        )
    }.stateIn(
        scope = scope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = PushHomeUiState(),
    )

    init {
        scope.launch {
            val state = graph.repository.state.first()
            if (state.pairing != null) {
                // The pairing token is single-use; only retry a pairing whose initial sync never completed.
                if (state.lastTokenSyncAtEpochMs == null) {
                    graph.syncCoordinator.resyncActiveTransport()
                }
                // Re-read delivery mode & drain any queued pull notifications on open.
                graph.pullCoordinator.pullNowAsync()
            }
        }
    }

    fun consumeLocalMessage() {
        localMessage.value = null
    }

    /** Resources, not concatenated English: these reach a Toast like every other user-facing string. */
    private fun string(resId: Int, vararg args: Any): String =
        getApplication<Application>().getString(resId, *args)

    /** Clears the stored credential and TLS pin, keeping mail. The recovery for a rotated server
     *  certificate or a device secret stranded by an interrupted PIN change — neither of which is
     *  a reason to delete the mailbox. See [PushRepository.resetPairingCredential]. */
    fun reconnectToServer() {
        scope.launch {
            isWorking.value = true
            graph.repository.resetPairingCredential()
            localMessage.value = string(org.kysecurity.mail.R.string.push_pairing_reconnect_done)
            isWorking.value = false
        }
    }

    /** Applies a pairing PushPairingActivity has already parsed and confirmed. */
    fun applyPairing(pairing: PairingData) {
        scope.launch {
            isWorking.value = true
            applyParsedPairing(pairing)
        }
    }

    private suspend fun applyParsedPairing(pairing: PairingData) {
        // No re-resolution here: [NativePairingDeepLinkParser] emits an already-resolved
        // registrationUrl, so this is a `PairingData` that is valid by construction. The coordinator
        // still re-derives it for *stored* pairings, which is a different concern — a host
        // divergence written by an older build left those clients unpinned.
        when {
            pairing.serverUrl.isBlank() -> {
                localMessage.value = string(org.kysecurity.mail.R.string.push_pairing_result_missing_server)
                isWorking.value = false
            }
            else -> {
                val result = graph.syncCoordinator.attemptPairing(pairing)
                if (result is NativeRegistrationResult.Success) {
                    // If the server put this user in pull mode, start fetching immediately.
                    graph.pullCoordinator.pullNowAsync()
                    pairedChannel.trySend(Unit)
                }
                localMessage.value = when (result) {
                    is NativeRegistrationResult.Success ->
                        string(org.kysecurity.mail.R.string.push_pairing_result_paired)
                    is NativeRegistrationResult.Error -> string(
                        if (result.expiredPairingToken) {
                            org.kysecurity.mail.R.string.push_pairing_result_failed_rescan
                        } else {
                            org.kysecurity.mail.R.string.push_pairing_result_failed
                        },
                        result.message,
                    )
                }
                isWorking.value = false
            }
        }
    }

    fun unpairDevice() {
        scope.launch {
            isWorking.value = true
            val result = graph.repository.unpairDevice(graph.deregisterClient)
            localMessage.value = when (val network = result.deregister) {
                is DeregisterResult.Success -> "Device unpaired"
                is DeregisterResult.Error -> "Unpaired locally (server update failed: ${network.message})"
            }
            isWorking.value = false
            // Pairing proof is already gone, so nothing downstream can tell that this account's
            // data outlived it. Same escalation the account-replacement path makes: erase rather
            // than leave the device pairable with another account's mail and contacts on it.
            if (result.cleanupIncomplete) {
                android.util.Log.e("PushHome", "Wiping: unpair could not purge ${result.residue}")
                localMessage.value = "Could not remove this account's data (${result.residue}); erasing this device instead"
                org.kysecurity.mail.security.SecurityWipe.wipeAndResetApp(getApplication())
            }
        }
    }

    /** Starts the flow only; the endpoint arrives via KyPostUnifiedPushService.onNewEndpoint. */
    fun switchToUnifiedPush(activity: Activity) {
        isWorking.value = true
        UnifiedPushRegistrar.beginRegistration(activity) { success, error ->
            isWorking.value = false
            localMessage.value = if (success) {
                "Switching to UnifiedPush — waiting for the distributor to confirm"
            } else {
                error ?: "UnifiedPush setup was canceled"
            }
        }
    }

    /** Switches this device back to Firebase and unregisters from the UnifiedPush distributor. */
    fun switchToFirebase() {
        scope.launch {
            isWorking.value = true
            UnifiedPushRegistrar.unregister(getApplication())
            val result = graph.syncCoordinator.syncCurrentPairingToken()
            localMessage.value = when (result) {
                is NativeRegistrationResult.Success -> "Switched to Firebase"
                is NativeRegistrationResult.Error -> "Failed to switch to Firebase: ${result.message}"
            }
            isWorking.value = false
        }
    }

    fun resyncToken() {
        scope.launch {
            isWorking.value = true
            val result = graph.syncCoordinator.resyncActiveTransport()
            if (result is NativeRegistrationResult.Success) {
                graph.pullCoordinator.pullNowAsync()
            }
            localMessage.value = when (result) {
                is NativeRegistrationResult.Success -> "Token synced"
                is NativeRegistrationResult.Error -> {
                    val suffix = if (result.expiredPairingToken) " — rescan the pairing QR code" else ""
                    "Token sync failed: ${result.message}$suffix"
                }
            }
            isWorking.value = false
        }
    }

    override fun onCleared() {
        scope.cancel()
        super.onCleared()
    }
}

data class PushHomeUiState(
    val pairing: PairingData? = null,
    val lastTokenSyncAtEpochMs: Long? = null,
    val syncError: String? = null,
    val latestPayload: PushPayload? = null,
    val history: List<PushPayload> = emptyList(),
    val deliveryMode: DeliveryMode = DeliveryMode.PUSH,
    val transport: PushTransport? = null,
    val isWorking: Boolean = false,
    val localMessage: String? = null,
)
