package org.kysecurity.mail.pgp

import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Owns attachment arrays until rendering accepts them. Record ownership INSIDE the worker:
 *  withContext may discard its return value when delivery to the cancelled caller resumes. */
internal suspend fun deliverReadOutcome(
    dispatcher: CoroutineDispatcher = Dispatchers.Default,
    read: suspend () -> ReadOutcome,
    render: (ReadOutcome) -> Boolean,
) {
    var pending: ReadOutcome? = null
    try {
        val outcome = withContext(dispatcher) { read().also { pending = it } }
        if (render(outcome)) pending = null
    } finally {
        (pending as? ReadOutcome.Decrypted)?.body?.attachments?.forEach { it.bytes.fill(0) }
    }
}
