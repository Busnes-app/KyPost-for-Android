package org.kysecurity.mail.contacts

import android.content.Context
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory

class ContactsGraph(context: Context) {
    private val appContext = context.applicationContext
    private val database = DataRuntime.graph(appContext).database

    // Shared by both clients: contact/group sync sends the same deviceSecret credential as mail.
    private val pinnedCallFactory = pinnedPairingCallFactory(appContext)

    val repository = ContactSyncRepository(
        db = database,
        client = ContactSyncClient(callFactory = pinnedCallFactory),
        cursorStore = ContactCursorStore(appContext, database),
        pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() },
        ownerStore = PushRuntime.graph(appContext).repository,
    )
    val coordinator = ContactSyncCoordinator(repository)
    val groupSyncRepository = GroupSyncRepository(
        db = database,
        client = GroupsSyncClient(callFactory = pinnedCallFactory),
        pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() },
    )
}

object ContactsRuntime {
    private val holder = SingletonGraph(::ContactsGraph)

    fun graph(context: Context): ContactsGraph = holder.get(context)

    fun invalidate() = holder.invalidate()
}
