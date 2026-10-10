package org.kysecurity.mail

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome

/** The relay send outlives the Compose instance that started it. A rotation destroys that
 *  instance mid-send; the replacement adopts this send instead of offering Send again. */
internal object ComposeSend : ProcessScopedState {

    class InFlight(val draft: MailDraft, val outcome: Deferred<MailOutcome<MailSendOutcome>>)

    /** Holds the draft, so it is session state that a wipe must drop. */
    @Volatile
    private var inFlight: InFlight? = null

    init {
        ProcessState.register(this)
    }

    /** [scope] must outlive the Activity: the app scope, not `lifecycleScope`. */
    fun start(
        scope: CoroutineScope,
        draft: MailDraft,
        send: (MailDraft) -> MailOutcome<MailSendOutcome>,
    ): InFlight {
        val outcome = scope.async {
            runCatching { send(draft) }.getOrElse { MailOutcome.UpstreamFailure(it.message ?: "Unexpected error") }
        }
        return InFlight(draft, outcome).also { inFlight = it }
    }

    fun current(): InFlight? = inFlight

    /** Only [sent] itself: a later send must not be dropped by an older one's late completion. */
    fun clear(sent: InFlight) {
        if (inFlight === sent) inFlight = null
    }

    override fun resetForNewSession() {
        inFlight = null
    }
}
