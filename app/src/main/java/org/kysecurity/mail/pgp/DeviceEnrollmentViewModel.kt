package org.kysecurity.mail.pgp

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import org.kysecurity.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

/** Owns one ceremony across rotations: an Activity-owned one would remint the keypair on rotate. */
internal class DeviceEnrollmentViewModel(application: Application) : AndroidViewModel(application) {

    private val _state = MutableStateFlow<EnrollmentUiState>(EnrollmentUiState.CheckingIdentity)
    val state: StateFlow<EnrollmentUiState> = _state.asStateFlow()

    /** True when no polling window is running. The Activity offers "Check again" on this, because
     *  `ShowingCode` means two different things depending on whether a window is open behind it. */
    private val _idle = MutableStateFlow(false)
    val idle: StateFlow<Boolean> = _idle.asStateFlow()

    /** The live Activity, or null between destroy and the next install. Volatile: cross-dispatcher. */
    @Volatile
    private var activitySealer: VaultSealer? = null

    @Volatile
    private var activityOpener: VaultOpener? = null

    private val ceremony = EnrollmentCeremony(
        identity = AndroidIdentitySource(application),
        transport = AndroidEnrollmentTransport(application),
        keys = AndroidEnrollmentKeys,
        // A proxy, not the Activity: the ViewModel outlives it. With none installed, seal() is Cancelled.
        sealer = object : VaultSealer {
            override suspend fun seal(plaintext: ByteArray, kind: VaultRecordKind, ack: EnrollmentReport.Keyring?): SealOutcome =
                activitySealer?.seal(plaintext, kind, ack) ?: SealOutcome.Cancelled
        },
        previousVault = object : VaultOpener {
            override suspend fun open(): OpenOutcome =
                activityOpener?.open() ?: OpenOutcome.Cancelled

            override fun sealedKind(): VaultRecordKind? = activityOpener?.sealedKind()
        },
        mailCache = RoomDecryptedMailCache(application),
        clock = SystemEnrollmentClock,
        hostileLocationEnabled = {
            SecurityRuntime.graph(application).hostileLocationSettings.isEnabled()
        },
        hasSecureLockScreen = { hasSecureLockScreen(application) },
        onState = { _state.value = it },
    )

    init {
        viewModelScope.launch {
            try {
                ceremony.run()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    fun installVaultPorts(sealer: VaultSealer?, opener: VaultOpener?) {
        activitySealer = sealer
        activityOpener = opener
    }

    /** Reopens a polling window against the same keypair. Ignored while one is already running, so
     *  a double tap cannot start two. */
    fun checkAgain() {
        if (!_idle.value) return
        _idle.value = false
        viewModelScope.launch {
            try {
                ceremony.checkAgain()
            } finally {
                _idle.value = ceremony.isIdle
            }
        }
    }

    /** Safe mid-flight: the seal uses the vault key, which `teardown()` never touches. */
    override fun onCleared() {
        ceremony.teardown()
        super.onCleared()
    }
}
