package org.kysecurity.mail

import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicLong

/** State in a process-scoped `object` that must be reset by hand at a session boundary. */
interface ProcessScopedState {
    /** Must be safe from any thread, callable more than once, and must not throw. */
    fun resetForNewSession()
}

object ProcessState {
    private const val TAG = "ProcessState"

    private val registered = CopyOnWriteArrayList<ProcessScopedState>()

    private val generation = AtomicLong()

    fun register(state: ProcessScopedState) {
        registered.addIfAbsent(state)
    }

    /** The current session. Capture it when work starts; [isCurrent] says whether it has ended. */
    fun generation(): Long = generation.get()

    fun isCurrent(token: Long): Boolean = generation.get() == token

    /** Resets every registered holder, isolating failures; returns the names that failed.
     *  The generation advances first, so work racing the reset already reads as expired. */
    fun resetAll(): List<String> {
        generation.incrementAndGet()
        val failed = mutableListOf<String>()
        registered.forEach { state ->
            runCatching { state.resetForNewSession() }.onFailure {
                val name = state::class.java.simpleName
                failed += name
                android.util.Log.e(TAG, "Failed to reset process-scoped state: $name", it)
            }
        }
        return failed
    }
}
