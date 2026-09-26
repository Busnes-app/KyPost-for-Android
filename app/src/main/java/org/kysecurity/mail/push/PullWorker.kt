package org.kysecurity.mail.push

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import org.kysecurity.mail.security.SecurityWipe
import java.util.concurrent.TimeUnit

/** WorkManager periodic at the platform minimum, armed whenever the device is paired. In PULL
 *  mode every tick polls; in PUSH mode it is the heartbeat, and [PullSyncCoordinator] polls only
 *  once the transport has been quiet past its threshold. Cancelled by unpair and security wipe. */
class PullWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        // Cancel, not skip: an abandoned wipe leaves credentials this worker turns into metadata.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("PullWorker", "Cancelling pull: a previous wipe was abandoned")
            PullScheduler.cancelPeriodic(applicationContext)
            return Result.success()
        }

        val graph = PushRuntime.graph(applicationContext)
        return when (graph.pullCoordinator.pullOnce()) {
            // Transient server/network failure — let WorkManager back off exponentially.
            is PullOutcome.Retry -> Result.retry()
            // Everything else (pulled, not paired, push healthy, 400/401) is terminal for this run;
            // the next periodic tick re-evaluates. 401 must not tight-loop, so never retry it here.
            else -> Result.success()
        }
    }
}

object PullScheduler {
    private const val PERIODIC_WORK_NAME = "kypost_pull_periodic"

    // WorkManager's hard floor for periodic work; documented as the baseline pull cadence.
    private const val PERIOD_MINUTES = 15L

    fun ensurePeriodic(context: Context) {
        val request = PeriodicWorkRequestBuilder<PullWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            // KEEP: don't reset the schedule (or its backoff) every time we re-arm.
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    fun cancelPeriodic(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(PERIODIC_WORK_NAME)
    }
}
