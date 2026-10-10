package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * The one "Add account" request a caller (Settings) is waiting on. Process-scoped rather than an
 * intent extra so it outlives the app-lock redirect, which finishes the screen it was sent to.
 * Exactly one answer reaches each request: the added account, or a cancellation. A new request,
 * a wipe or an unpair cancels the old one.
 */
object PendingAccountSetup : ProcessScopedState {
    private class Request(val onAdded: (accountName: String) -> Unit, val onCancelled: () -> Unit)

    private var held: Request? = null

    init { ProcessState.register(this) }

    val isPending: Boolean get() = synchronized(this) { held != null }

    /** Swaps in one step, then answers the displaced request outside the lock. */
    fun hold(onAdded: (accountName: String) -> Unit, onCancelled: () -> Unit) {
        val displaced = synchronized(this) { held.also { held = Request(onAdded, onCancelled) } }
        displaced?.onCancelled?.invoke()
    }

    fun complete(accountName: String) {
        take()?.onAdded?.invoke(accountName)
    }

    fun cancel() {
        take()?.onCancelled?.invoke()
    }

    override fun resetForNewSession() = cancel()

    private fun take(): Request? = synchronized(this) { held.also { held = null } }
}
