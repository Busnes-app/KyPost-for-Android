package org.kysecurity.mail.contacts.device

import android.content.Context
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.security.HostileLocationSettings

class DeviceContactsGraph(context: Context) {
    private val appContext = context.applicationContext
    private val hostileLocationSettings = HostileLocationSettings(appContext)
    val settings = DeviceContactSyncSettings(appContext)
    val accountManager = DeviceContactAccountManager(appContext)
    val repository = DeviceContactRepository(
        context = appContext,
        db = DataRuntime.graph(appContext).database,
        syncRepository = ContactsRuntime.graph(appContext).repository,
        groupSyncRepository = ContactsRuntime.graph(appContext).groupSyncRepository,
    )
    val coordinator = DeviceContactSyncCoordinator(
        syncAll = repository::syncAll,
        enabled = settings::isEnabled,
        hostileLocationEnabled = { hostileLocationSettings.isEnabled() },
    )
    val observer = DeviceContactObserver(appContext, coordinator)

    /** True when contact sync may run at all right now — see [DeviceContactSyncCoordinator]'s
     *  `hostileLocationEnabled` for why protection vetoes it. */
    fun syncPermitted(): Boolean = !hostileLocationSettings.isEnabled()

    fun bootstrapIfEnabled() {
        if (!settings.isEnabled()) return
        if (!syncPermitted()) {
            // Protection was turned on while sync was enabled; make sure the periodic worker
            // isn't left armed from a previous session.
            DeviceContactSyncScheduler.cancelPeriodic(appContext)
            return
        }
        DeviceContactSyncScheduler.ensurePeriodic(appContext)
    }
}

object DeviceContactsRuntime {
    private val holder = SingletonGraph(::DeviceContactsGraph)

    fun graph(context: Context): DeviceContactsGraph = holder.get(context)

    fun invalidate() = holder.invalidate()
}
