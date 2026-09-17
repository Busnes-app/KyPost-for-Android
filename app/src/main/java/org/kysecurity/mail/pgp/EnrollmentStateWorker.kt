package org.kysecurity.mail.pgp

import android.content.Context
import androidx.annotation.VisibleForTesting
import androidx.work.BackoffPolicy
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.OneTimeWorkRequest
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import java.util.concurrent.TimeUnit

/** What to do after one attempt at reporting. Kept apart from `ListenableWorker.Result` so the
 *  decision can be asserted on the JVM, without a device. */
internal enum class EnrollmentReportOutcome { DONE, RETRY, GIVE_UP }

/** WorkManager imposes no retry ceiling of its own, so an unbounded RETRY never terminates. */
internal const val MAX_REPORT_ATTEMPTS = 8

/** Retry whenever the server's marker is wrong in the unsafe direction; give up otherwise. */
internal fun enrollmentReportOutcome(
    result: EnrollmentCallResult,
    runAttemptCount: Int = 0,
): EnrollmentReportOutcome =
    when (result) {
        is EnrollmentCallResult.Ok -> EnrollmentReportOutcome.DONE
        is EnrollmentCallResult.RateLimited, is EnrollmentCallResult.Failed ->
            if (runAttemptCount >= MAX_REPORT_ATTEMPTS) EnrollmentReportOutcome.GIVE_UP
            else EnrollmentReportOutcome.RETRY
        is EnrollmentCallResult.Unauthorized, is EnrollmentCallResult.NotFound -> EnrollmentReportOutcome.GIVE_UP
        // The server compared the claim with its delivery record and refused; repeating it cannot help.
        is EnrollmentCallResult.Conflict -> EnrollmentReportOutcome.GIVE_UP
        // Only fetchEnvelope produces this; reportState cannot. Not a retry: a response this route
        // has no way to send means the client is talking to something that is not this API.
        is EnrollmentCallResult.Envelope -> EnrollmentReportOutcome.GIVE_UP
    }

/** Whether a report attempt spends the teardown marker: only when the correction landed, or no
 *  device row remains to correct. Transient results keep it even past the attempt ceiling, which
 *  [enrollmentReportOutcome] deliberately folds into GIVE_UP: the worker is re-enqueued on every
 *  unlock, and with no record on disk the same "not enrolled" stays truthful however long it waits. */
internal fun teardownReportSpent(result: EnrollmentCallResult): Boolean = when (result) {
    is EnrollmentCallResult.Ok, is EnrollmentCallResult.Unauthorized, is EnrollmentCallResult.NotFound -> true
    is EnrollmentCallResult.RateLimited, is EnrollmentCallResult.Failed -> false
    // NotEnrolled cannot be refused, and this route never returns an envelope; nothing to keep waiting for.
    is EnrollmentCallResult.Conflict, is EnrollmentCallResult.Envelope -> true
}

/** Reports enrollment state durably; offline is expected, so it retries rather than drops. */
internal class EnrollmentStateWorker(
    context: Context,
    params: WorkerParameters,
) : CoroutineWorker(context, params) {

    override suspend fun doWork(): Result {
        // Before the credential is even read. This worker exists to tell the server what key
        // material this device holds; after an abandoned wipe that is a claim the app has no
        // business making, on a device it failed to erase.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("EnrollmentStateWorker", "Skipping state report: a previous wipe was abandoned")
            return Result.success()
        }

        // Read at run time, never carried in inputData: WorkManager writes input to its own
        // database in plaintext, and this is the credential every authenticated call uses.
        val pairing = PushRuntime.graph(applicationContext).repository.pairingForAuthenticatedCall()
            // Unpaired: there is no device row left to correct. SecurityWipe's path lands here.
            ?: return Result.success()
        val deviceId = pairing.deviceId
        val deviceSecret = pairing.deviceSecret
        if (deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Gated and locked: only a PIN unlock helps, and UnlockActivity re-enqueues us. Do not retry.
            return Result.success()
        }

        val vault = EnrollmentVault(applicationContext)
        val tornDown = vault.teardownReportPending()
        val report = enrollmentReportFor(probeEnrollment(vault), vault.keyringAck(), tornDown)
            ?: return Result.success()

        // The pinned factory, as every client carrying the device credential uses; the default is unpinned.
        val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(applicationContext))
        val result = clients.reportState(pairing.serverUrl, deviceId, deviceSecret, report)
        if (tornDown && teardownReportSpent(result)) vault.clearTeardownReport()
        return when (enrollmentReportOutcome(result, runAttemptCount)) {
            EnrollmentReportOutcome.DONE -> Result.success()
            EnrollmentReportOutcome.RETRY -> Result.retry()
            EnrollmentReportOutcome.GIVE_UP -> Result.failure()
        }
    }

    companion object {
        const val UNIQUE_NAME = "kypost_enrollment_state_report"

        /** Separate from [enqueue] so a test can read what would be enqueued without a scheduler
         *  running it. The request carries no input data; see [doWork]. */
        @VisibleForTesting
        internal fun buildRequest(): OneTimeWorkRequest =
            OneTimeWorkRequestBuilder<EnrollmentStateWorker>()
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, 30, TimeUnit.SECONDS)
                .build()

        fun enqueue(context: Context) {
            WorkManager.getInstance(context.applicationContext)
                // REPLACE, not KEEP: the worker re-probes live state on every run, so the newest
                // request is always the truthful one and a stale pending report is worth nothing.
                .enqueueUniqueWork(UNIQUE_NAME, ExistingWorkPolicy.REPLACE, buildRequest())
        }
    }
}
