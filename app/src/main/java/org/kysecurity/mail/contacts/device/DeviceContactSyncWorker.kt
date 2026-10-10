package org.kysecurity.mail.contacts.device

import android.content.Context
import androidx.work.Constraints
import androidx.work.CoroutineWorker
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.NetworkType
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import androidx.work.WorkerParameters
import java.util.concurrent.TimeUnit

class DeviceContactSyncWorker(
    appContext: Context,
    params: WorkerParameters,
) : CoroutineWorker(appContext, params) {

    override suspend fun doWork(): Result {
        val graph = DeviceContactsRuntime.graph(applicationContext)
        // This worker calls the repository directly, so the coordinator's vetoes are repeated here.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e("DeviceContactSyncWorker", "Cancelling sync: a previous wipe was abandoned")
            DeviceContactSyncScheduler.cancelPeriodic(applicationContext)
            return Result.success()
        }
        if (!graph.syncPermitted() || !graph.settings.isEnabled()) {
            DeviceContactSyncScheduler.cancelPeriodic(applicationContext)
            return Result.success()
        }
        // syncAll() reports failed stages rather than throwing, so the retry decision reads them
        // rather than a catch that no real failure reaches.
        return try {
            val failedStages = runContactSync(
                server = { org.kysecurity.mail.contacts.ContactsRuntime.graph(applicationContext).repository.sync() },
                device = { graph.repository.syncAll() },
            )
            if (failedStages.isEmpty()) {
                Result.success()
            } else {
                android.util.Log.e("DeviceContactSyncWorker", "Sync stages failed: $failedStages")
                Result.retry()
            }
        } catch (e: kotlinx.coroutines.CancellationException) {
            // WorkManager stopped us; not a sync failure.
            throw e
        } catch (e: Exception) {
            android.util.Log.e("DeviceContactSyncWorker", "Sync threw before any stage could report", e)
            Result.retry()
        }
    }
}

/** The background pass: server first, so the phone gets the newest contacts and the outbox drains;
 *  then the device. Device edits queued by this pass go to the server on the next one. A server
 *  failure does not skip the device pass, which is local. Returns the failed stage names. */
internal suspend fun runContactSync(
    server: suspend () -> org.kysecurity.mail.contacts.ContactSyncOutcome,
    device: suspend () -> List<String>,
): List<String> {
    val serverFailed = server() !is org.kysecurity.mail.contacts.ContactSyncOutcome.Success
    return listOfNotNull("serverSync".takeIf { serverFailed }) + device()
}

object DeviceContactSyncScheduler {
    private const val PERIODIC_WORK_NAME = "kypost_device_contact_sync_periodic"
    private const val PERIOD_MINUTES = 15L

    fun ensurePeriodic(context: Context) {
        val request = PeriodicWorkRequestBuilder<DeviceContactSyncWorker>(PERIOD_MINUTES, TimeUnit.MINUTES)
            .setConstraints(
                Constraints.Builder()
                    .setRequiredNetworkType(NetworkType.CONNECTED)
                    .build(),
            )
            .build()

        WorkManager.getInstance(context.applicationContext).enqueueUniquePeriodicWork(
            PERIODIC_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request,
        )
    }

    fun cancelPeriodic(context: Context) {
        WorkManager.getInstance(context.applicationContext).cancelUniqueWork(PERIODIC_WORK_NAME)
    }
}
