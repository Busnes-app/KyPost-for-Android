package org.kysecurity.mail.contacts.device

import android.accounts.Account
import android.app.Service
import android.content.AbstractThreadedSyncAdapter
import android.content.ContentProviderClient
import android.content.Intent
import android.content.SyncResult
import android.os.Bundle
import android.os.IBinder

/**
 * Exists so the platform knows KyPost is the sync adapter for its contacts account. Sync itself
 * is driven by DeviceContactSyncCoordinator and DeviceContactSyncWorker, which apply the
 * enable, Hostile Location and wipe gates; a system-initiated pass does nothing.
 */
class KyPostContactSyncService : Service() {
    private val adapter by lazy { NoOpSyncAdapter(this) }

    override fun onBind(intent: Intent?): IBinder = adapter.syncAdapterBinder

    private class NoOpSyncAdapter(service: Service) : AbstractThreadedSyncAdapter(service, true) {
        override fun onPerformSync(
            account: Account?,
            extras: Bundle?,
            authority: String?,
            provider: ContentProviderClient?,
            syncResult: SyncResult?,
        ) = Unit
    }
}
