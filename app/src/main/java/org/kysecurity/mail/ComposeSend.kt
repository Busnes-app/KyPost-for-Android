package org.kysecurity.mail

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Deferred
import kotlinx.coroutines.async
import okhttp3.Call
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference

/** The relay send outlives the Compose instance that started it. A rotation destroys that
 *  instance mid-send; the replacement adopts this send instead of offering Send again.
 *
 *  It does not outlive the session: [resetForNewSession] cancels every send still running, the
 *  coroutine and its HTTP call, waits for them to finish and zeroes their attachments. */
internal object ComposeSend : ProcessScopedState {

    class InFlight internal constructor(
        val draft: MailDraft,
        val outcome: Deferred<MailOutcome<MailSendOutcome>>,
        private val call: CallHandle,
    ) {
        internal fun cancel() {
            outcome.cancel()
            call.cancel()
        }
    }

    /** The send's HTTP call. Attach and cancel may race; whichever runs second cancels it. */
    internal class CallHandle {
        private val call = AtomicReference<Call?>()

        @Volatile
        private var cancelled = false

        fun attach(newCall: Call) {
            call.set(newCall)
            if (cancelled) newCall.cancel()
        }

        fun cancel() {
            cancelled = true
            call.get()?.cancel()
        }
    }

    private val lock = Any()

    /** The send a recreated Compose may adopt. */
    private var inFlight: InFlight? = null

    /** Every send until it completes, adopted or not: what a reset has to stop. */
    private val running = mutableSetOf<InFlight>()

    init {
        ProcessState.register(this)
    }

    /** [scope] must outlive the Activity: the app scope, not `lifecycleScope`. [send] must hand
     *  its HTTP call to the callback so a reset can cancel it. */
    fun start(
        scope: CoroutineScope,
        draft: MailDraft,
        send: (MailDraft, onCall: (Call) -> Unit) -> MailOutcome<MailSendOutcome>,
    ): InFlight {
        val call = CallHandle()
        // Launched and registered under the lock, so a concurrent reset either sees it or precedes it.
        val sending = synchronized(lock) {
            val outcome = scope.async {
                runCatching { send(draft, call::attach) }
                    .getOrElse { MailOutcome.UpstreamFailure(it.message ?: "Unexpected error") }
            }
            InFlight(draft, outcome, call).also {
                running += it
                inFlight = it
            }
        }
        sending.outcome.invokeOnCompletion { synchronized(lock) { running -= sending } }
        return sending
    }

    fun current(): InFlight? = synchronized(lock) { inFlight }

    /** Only [sent] itself: a later send must not be dropped by an older one's late completion. */
    fun clear(sent: InFlight) = synchronized(lock) {
        if (inFlight === sent) inFlight = null
    }

    override fun resetForNewSession() {
        val stopping = synchronized(lock) {
            inFlight = null
            running.toList()
        }
        val finished = CountDownLatch(stopping.size)
        stopping.forEach {
            it.outcome.invokeOnCompletion { finished.countDown() }
            it.cancel()
        }
        // A cancelled job completes only once its blocking body returns, so this waits for the call.
        // ponytail: bounded like MailBackgroundExecutor.quiesce; a read that ignores cancel outlives it.
        finished.await(STOP_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        stopping.forEach { sending -> sending.draft.attachments.forEach { it.wipe() } }
    }

    private const val STOP_TIMEOUT_MS = 2_000L
}
