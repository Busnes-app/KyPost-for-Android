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
    /** The request whose setup screen the app-lock redirect closed, to resume once after unlock. */
    private var interrupted: Long? = null

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

    /** Completes only while [token]'s request is the one held. */
    fun complete(token: Long, accountName: String) {
        takeIf(token)?.onAdded?.invoke(accountName)
    }

    /** [token]'s setup screen was closed by the app-lock redirect; see [takeInterrupted]. */
    fun markInterrupted(token: Long) {
        synchronized(this) { if (held?.token == token) interrupted = token }
    }

    /** The interrupted request to resume, once, and only while it is still the one held. */
    fun takeInterrupted(): Long? = synchronized(this) { interrupted.also { interrupted = null }?.takeIf { it == held?.token } }

    fun cancel() {
        take()?.onCancelled?.invoke()
    }

    /** Cancels only while [token]'s request is the one held. */
    fun cancel(token: Long) {
        takeIf(token)?.onCancelled?.invoke()
    }

    override fun resetForNewSession() = cancel()

    private fun take(): Request? = synchronized(this) { held.also { held = null; interrupted = null } }

    private fun takeIf(token: Long): Request? =
        synchronized(this) { held?.takeIf { it.token == token }?.also { held = null; interrupted = null } }
}
