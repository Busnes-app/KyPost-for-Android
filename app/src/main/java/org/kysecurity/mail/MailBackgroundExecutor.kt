package org.kysecurity.mail

import android.content.Context
import android.widget.Toast
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.userFacingMessage
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

/** Short on purpose: the caller is a teardown that must not block on an unreachable server. */
private const val QUIESCE_TIMEOUT_MS = 2_000L

private const val TAG = "MailBackground"

// Mail mutations outlive the Activity that fired them, so the UI can update optimistically.
object MailBackgroundExecutor {
    /** Null means suspended, and that is the whole point: a wipe that swapped in a fresh pool
     *  stopped the work already running and then opened a new lane for more, right as the database
     *  it writes to was being closed and deleted. Every mutation of this field, and every
     *  submission, happens under this object's monitor so a task cannot be handed to a pool that
     *  [quiesce] has already taken away. */
    private var executor: ExecutorService? = Executors.newFixedThreadPool(2)

    /** Nested quiesce is ONE suspension: the wipe quiesces, and its own database step quiesces
     *  again. Only the outermost [resume] may put mail work back on the road. */
    private var suspensions = 0

    /** The outermost [quiesce]'s verdict, reported to nested callers that have nothing to await. */
    @Volatile
    private var settled = true

    /** Never lets a task throw out of the pool. An uncaught exception on an executor thread kills
     *  the process, and these tasks run blocking mail I/O whose failure modes include `quiesce()`
     *  interrupting them mid-call — a routine event during a wipe or a protection toggle, not a bug
     *  worth a crash. [submitReporting] already had this; the fire-and-forget path did not. */
    fun submit(onDropped: () -> Unit = {}, task: () -> Unit) {
        post(onDropped) {
            runCatching(task).onFailure { android.util.Log.e(TAG, "Background mail task threw", it) }
        }
    }

    /** Toasts against the application context: the Activity that started this has usually finished.
     *  [onFailure] runs on the main thread first and returns true when a live screen showed it.
     *  [onDropped] runs instead of [task] if the task is refused or discarded unrun. */
    fun submitReporting(
        context: Context,
        actionLabel: String,
        onFailure: ((reason: String) -> Boolean)? = null,
        onDropped: () -> Unit = {},
        task: () -> MailOutcome<*>,
    ) {
        val appContext = context.applicationContext
        post(onDropped) {
            val outcome = runCatching { task() }.getOrElse { error ->
                android.util.Log.e(TAG, "$actionLabel threw", error)
                MailOutcome.UpstreamFailure(error.message ?: "Unexpected error")
            }
            if (outcome is MailOutcome.Success) return@post
            val reason = outcome.userFacingMessage().orEmpty()
            android.util.Log.w(TAG, "$actionLabel failed: $reason")
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                if (onFailure?.invoke(reason) == true) return@post
                Toast.makeText(
                    appContext,
                    appContext.getString(R.string.mail_action_failed, actionLabel, reason),
                    Toast.LENGTH_LONG,
                ).show()
            }
        }
    }

    /** Drops [work] while suspended rather than running it or throwing. `execute` on a pool that
     *  [quiesce] has shut down throws `RejectedExecutionException` at whichever thread submitted —
     *  a UI thread, for a tap that arrived while the app was being wiped. The tap is refused
     *  either way; the difference is a log line instead of a crash. */
    private fun post(onDropped: () -> Unit, work: Runnable) {
        synchronized(this) {
            val pool = executor
            if (pool != null) {
                pool.execute(DroppableTask(work, onDropped))
                return
            }
        }
        android.util.Log.w(TAG, "Dropped a mail task: background work is suspended")
        runCatching(onDropped)
    }

    /** A queued task [quiesce] discards still gets to release what its submitter claimed. */
    private class DroppableTask(private val work: Runnable, val onDropped: () -> Unit) : Runnable by work

    /** Stops in-flight work AND refuses new work until the matching [resume]; best-effort on the
     *  stopping, since socket reads ignore interrupts. Returns whether the running work finished.
     *
     *  Callers must balance this in a `finally` — the pool does not come back on its own, and mail
     *  actions stay dead for the rest of the process if one does not. */
    fun quiesce(): Boolean {
        val previous = synchronized(this) {
            suspensions++
            executor.also { executor = null }
        } ?: return settled // Already suspended by an enclosing scope; nothing left to await.
        previous.shutdownNow().forEach { (it as? DroppableTask)?.onDropped?.let(::runCatching) }
        // awaitTermination returns false on timeout and throws only on interruption; report that.
        val awaited = try {
            previous.awaitTermination(QUIESCE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
        } catch (e: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
        if (!awaited) {
            android.util.Log.w(TAG, "Mail work did not quiesce within ${QUIESCE_TIMEOUT_MS}ms")
        }
        settled = awaited
        return awaited
    }

    /** Idempotent, and deliberately: an unbalanced call must not wedge mail work off permanently,
     *  and must not hand out a second pool while a wipe still holds the first suspension. */
    fun resume() {
        synchronized(this) {
            if (suspensions > 0) suspensions--
            if (suspensions == 0 && executor == null) {
                executor = Executors.newFixedThreadPool(2)
            }
        }
    }
}
