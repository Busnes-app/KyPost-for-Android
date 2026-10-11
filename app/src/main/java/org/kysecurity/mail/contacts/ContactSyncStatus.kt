package org.kysecurity.mail.contacts

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.update
import org.kysecurity.mail.data.PendingContactSummary

const val STUCK_AFTER_FAILURES = 3
const val STUCK_OUTBOX_AGE_MS = 60 * 60 * 1000L

data class ContactSyncFailures(val count: Int = 0, val last: ContactSyncOutcome? = null)

sealed class ContactSyncStatus {
    object Idle : ContactSyncStatus()
    data class Waiting(val pending: Int) : ContactSyncStatus()
    /** [reason] is the latest failed outcome this process saw, null if none. */
    data class Stuck(val pending: Int, val reason: ContactSyncOutcome?) : ContactSyncStatus()
}

/** Consecutive server-sync failures. ponytail: in memory, so a restart forgets them; the outbox
 *  age still catches a change that never leaves. Persist it if that proves too forgetful. */
class ContactSyncHealth {
    private val state = MutableStateFlow(ContactSyncFailures())
    val failures: StateFlow<ContactSyncFailures> = state

    fun record(outcome: ContactSyncOutcome) = when (outcome) {
        ContactSyncOutcome.Success -> state.value = ContactSyncFailures()
        ContactSyncOutcome.NotPaired -> Unit
        else -> state.update { ContactSyncFailures(it.count + 1, outcome) }
    }
}

fun contactSyncStatusOf(
    pending: PendingContactSummary,
    failures: ContactSyncFailures,
    nowMs: Long,
): ContactSyncStatus {
    val oldest = pending.oldestAtEpochMs
    val stuckInOutbox = pending.count > 0 && oldest != null && nowMs - oldest > STUCK_OUTBOX_AGE_MS
    return when {
        stuckInOutbox || failures.count >= STUCK_AFTER_FAILURES -> ContactSyncStatus.Stuck(pending.count, failures.last)
        pending.count > 0 -> ContactSyncStatus.Waiting(pending.count)
        else -> ContactSyncStatus.Idle
    }
}
