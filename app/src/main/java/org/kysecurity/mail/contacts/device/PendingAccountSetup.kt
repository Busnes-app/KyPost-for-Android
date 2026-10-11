package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.ProcessScopedState
import org.kysecurity.mail.ProcessState

/**
 * The one "Add account" request a caller (Settings) is waiting on. Process-scoped rather than an
 * intent extra so it outlives the app-lock redirect, which finishes the screen it was sent to.
 * Exactly one answer reaches each request: the added account, or a cancellation. A new request,
 * a wipe or an unpair cancels the old one. Each request has a token its setup screen carries, so a
 * screen can only cancel the request it was opened for.
 */
object PendingAccountSetup : ProcessScopedState {
    private class Request(val token: Long, val onAdded: (accountName: String) -> Unit, val onCancelled: () -> Unit)

    private var held: Request? = null
    private var lastToken = 0L

    init { ProcessState.register(this) }

    /** The held request's token, or null when nothing is waiting. */
    val pendingToken: Long? get() = synchronized(this) { held?.token }

    fun isCurrent(token: Long): Boolean = pendingToken == token

    /** Swaps in one step, then answers the displaced request outside the lock. */
    fun hold(onAdded: (accountName: String) -> Unit, onCancelled: () -> Unit): Long {
        val (token, displaced) = synchronized(this) {
            val request = Request(++lastToken, onAdded, onCancelled)
            request.token to held.also { held = request }
        }
        displaced?.onCancelled?.invoke()
        return token
    }

    fun complete(accountName: String) {
        take()?.onAdded?.invoke(accountName)
    }

    fun cancel() {
        take()?.onCancelled?.invoke()
    }

    /** Cancels only while [token]'s request is the one held. */
    fun cancel(token: Long) {
        synchronized(this) { held?.takeIf { it.token == token }?.also { held = null } }?.onCancelled?.invoke()
    }

    override fun resetForNewSession() = cancel()

    private fun take(): Request? = synchronized(this) { held.also { held = null } }
}
