package org.kysecurity.mail.push

import android.app.Activity
import android.app.Application
import androidx.lifecycle.AndroidViewModel
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.asContextElement
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class PushHomeViewModel(application: Application) : AndroidViewModel(application) {
    private val graph = PushRuntime.graph(application)
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)

    private val isWorking = MutableStateFlow(false)
    private val localMessage = MutableStateFlow<String?>(null)
    private val pendingApproval = ApprovalWait.card

    /** One element per registration that succeeded; conflated, so a stopped screen still gets it. */
    private val pairedChannel = Channel<Unit>(Channel.CONFLATED)
    val paired: Flow<Unit> = pairedChannel.receiveAsFlow()

    val uiState: StateFlow<PushHomeUiState> = combine(
        graph.repository.state,
        graph.repository.everPaired,
        isWorking,
        localMessage,
        pendingApproval,
    ) { repo, everPaired, working, local, approval ->
        PushHomeUiState(
            pairing = repo.pairing,
            lastTokenSyncAtEpochMs = repo.lastTokenSyncAtEpochMs,
            syncError = repo.syncError,
            latestPayload = repo.latestPayload,
            history = repo.history,
            deliveryMode = repo.deliveryMode,
            transport = repo.transport,
            everPaired = everPaired,
            isWorking = working,
            localMessage = local,
            pendingApproval = approval,
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

    /** The approval wait outlives the screen that started it, so its outcome is reported by the
     *  pairing screen that is started when it ends, or the next one to start. The Activity calls
     *  this inside `repeatOnLifecycle(STARTED)`: a stopped screen, which the app lock may finish
     *  on return, must not take it. */
    suspend fun reportApprovalResults(canShow: () -> Boolean) {
        ApprovalWait.result.filterNotNull().collect {
            // A screen the lock is finishing still reaches STARTED: leave the outcome for the next one.
            if (canShow()) ApprovalWait.takeResult()?.let(::reportPairing)
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
        // A newer confirmed link supersedes a request still waiting, or its late approval replaces this one.
        cancelApproval()
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
                isWorking.value = false
                if (result is NativeRegistrationResult.Pending) awaitApproval(result) else reportPairing(result)
            }
        }
    }

    /** Shows the waiting-for-approval card and polls until the web page decides. Internal so the
     *  instrumented screenshot test can show the card without a server. */
    internal fun awaitApproval(pending: NativeRegistrationResult.Pending) {
        // The app's scope, not this screen's: the user approves in a browser, and coming back past
        // the app lock finishes this screen. Cancelling then wiped a secret the web had approved.
        val approvalScope = (getApplication<Application>() as? org.kysecurity.mail.KyPostApp)?.appScope ?: scope
        ApprovalWait.start(
            PendingApprovalUi(
                approvalCode = pending.approvalCode,
                serverHost = pairingUrlHost(pending.pairing.serverUrl) ?: pending.pairing.serverUrl,
            ),
            approvalScope,
        ) {
            // Not reported here: this screen may be gone. ApprovalWait holds the result for the
            // next started pairing screen (reportApprovalResults). The first pull does not wait for it.
            graph.syncCoordinator.awaitApproval(pending).also {
                if (it is NativeRegistrationResult.Success) graph.pullCoordinator.pullNowAsync()
            }
        }
    }

    /** Cancel on the waiting card: stops polling and drops the pending credentials. */
    fun cancelApproval() = ApprovalWait.cancel()

    private fun reportPairing(result: NativeRegistrationResult) {
        if (result is NativeRegistrationResult.Success) {
            // If the server put this user in pull mode, start fetching immediately.
            graph.pullCoordinator.pullNowAsync()
            pairedChannel.trySend(Unit)
        }
        localMessage.value = when (result) {
            is NativeRegistrationResult.Success ->
                string(org.kysecurity.mail.R.string.push_pairing_result_paired)
            is NativeRegistrationResult.Error -> if (result.wipeOwed) {
                string(org.kysecurity.mail.R.string.push_pairing_blocked_wipe)
            } else if (result.notApproved) {
                string(org.kysecurity.mail.R.string.push_pairing_not_approved)
            } else {
                string(
                    if (result.expiredPairingToken) {
                        org.kysecurity.mail.R.string.push_pairing_result_failed_rescan
                    } else {
                        org.kysecurity.mail.R.string.push_pairing_result_failed
                    },
                    result.message,
                )
            }
            // Unreachable: callers route a Pending to awaitApproval.
            is NativeRegistrationResult.Pending -> null
        }
    }

    /** [keepContacts]: the Remove Pairing dialog's "Also remove this device's contacts", unticked (owner decision Q2). */
    fun unpairDevice(keepContacts: Boolean = true) {
        // A request still waiting would pair the device again the moment the web approved it.
        ApprovalWait.cancel()
        // NonCancellable, escalation included: leaving the screen mid-unpair cancelled this in the
        // deregister or halfway through the purge, leaving the device paired or its data behind.
        scope.launch {
            withContext(NonCancellable) {
                isWorking.value = true
                val result = graph.syncCoordinator.withRegistrationsHeld {
                    graph.repository.unpairDevice(graph.deregisterClient, keepContacts = keepContacts)
                }
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
                is NativeRegistrationResult.Pending -> "Failed to switch to Firebase: approval requested again"
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
                is NativeRegistrationResult.Pending -> "Token sync failed: the server asked to approve this device again"
            }
            isWorking.value = false
        }
    }

    override fun onCleared() {
        scope.cancel()
        super.onCleared()
    }
}

/** The one device-approval wait, held for the process rather than one pairing screen: the app
 *  lock finishes that screen, and the next one must still show the card and be able to cancel it,
 *  and report its outcome ([result]). A newer pairing link, an unpair and a session reset (wipe)
 *  cancel it. The coordinator wipes the pending secret on every way out. */
internal object ApprovalWait : org.kysecurity.mail.ProcessScopedState {
    val card = MutableStateFlow<PendingApprovalUi?>(null)

    /** How the last wait ended, until a pairing screen takes it ([takeResult]). */
    val result = MutableStateFlow<NativeRegistrationResult?>(null)
    private var job: Job? = null

    /** Set on the running wait's threads; see [resetForNewSession]. */
    private val runningWait = ThreadLocal<Any?>()
    private var token: Any? = null

    init {
        org.kysecurity.mail.ProcessState.register(this)
    }

    @Synchronized
    fun start(ui: PendingApprovalUi, scope: CoroutineScope, wait: suspend () -> NativeRegistrationResult) {
        job?.cancel()
        card.value = ui
        result.value = null
        lateinit var started: Job
        val mine = Any()
        started = scope.launch(runningWait.asContextElement(mine), start = kotlinx.coroutines.CoroutineStart.LAZY) {
            var outcome: NativeRegistrationResult? = null
            try {
                outcome = wait()
            } finally {
                finished(started, outcome)
            }
        }
        job = started
        token = mine
        started.start()
    }

    @Synchronized
    private fun finished(which: Job, outcome: NativeRegistrationResult?) {
        // A cancelled or superseded wait reports nothing.
        if (job !== which) return
        job = null
        token = null
        card.value = null
        result.value = outcome
    }

    /** Single-use: the first screen to take it reports it. */
    @Synchronized
    fun takeResult(): NativeRegistrationResult? = result.value.also { result.value = null }

    @Synchronized
    fun cancel() {
        job?.cancel()
        job = null
        token = null
        card.value = null
        result.value = null
    }

    /** Every other session end cancels the wait. The one exception is the reset the wait itself
     *  runs: an approved account replacement purges the old account inside `finishPairing`, and
     *  cancelling there dropped the result of the pairing it was finishing (no "Paired", no
     *  contacts question). */
    @Synchronized
    override fun resetForNewSession() {
        if (token != null && runningWait.get() === token) return
        cancel()
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
    // True until the store answers, so the review login cannot be reached on a paired install.
    val everPaired: Boolean = true,
    val isWorking: Boolean = false,
    val localMessage: String? = null,
    /** Non-null while a registration waits for approval on the web; the screen shows the card. */
    val pendingApproval: PendingApprovalUi? = null,
)

/** What the waiting card shows. No credentials: those stay with the coordinator's poll. */
data class PendingApprovalUi(val approvalCode: String, val serverHost: String)
