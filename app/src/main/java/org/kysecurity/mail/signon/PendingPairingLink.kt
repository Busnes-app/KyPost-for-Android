package org.kysecurity.mail.signon

import java.util.concurrent.atomic.AtomicReference
import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState
import org.kysecurity.mail.push.PairingData

/**
 * Carries a finished sign-on from the app scope to the pairing screen when the sign-on activity was
 * destroyed by the app lock in between. Holds the [PairingData] only, never the ID token. Single use.
 */
object PendingPairingLink : ProcessScopedState {
    private val held = AtomicReference<PairingData?>(null)

    init { ProcessState.register(this) }

    fun set(pairing: PairingData) = held.set(pairing)

    fun take(): PairingData? = held.getAndSet(null)

    override fun resetForNewSession() = held.set(null)
}
