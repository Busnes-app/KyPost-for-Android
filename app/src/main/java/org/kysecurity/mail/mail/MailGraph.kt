package org.kysecurity.mail.mail

import android.content.Context
import org.kysecurity.mail.SingletonGraph
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory

class MailGraph(context: Context) {
    private val appContext = context.applicationContext
    private val mailCursorStore = MailCursorStore(appContext)
    private val pairingProvider = { PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall() }
    private val relaySource: MailSource = MailRuntime.sourceForTest ?: RelayMailSource(
        pairingProvider = pairingProvider,
        cursorProvider = mailCursorStore,
        // The one shared pinned-or-refuse factory; a private provider here let mail downgrade.
        callFactory = pinnedPairingCallFactory(appContext),
    )

    val repository = MailRepository(
        emailDao = DataRuntime.graph(appContext).database.emailDao(),
        relaySource = relaySource,
        // The source reads the checkpoint to build `since`; only the repository advances it.
        cursorProvider = mailCursorStore,
    )
}

object MailRuntime {
    private val holder = SingletonGraph(::MailGraph)

    /** Instrumentation only: the source the next graph is built with. Null in production. */
    @androidx.annotation.VisibleForTesting
    @Volatile
    internal var sourceForTest: MailSource? = null

    fun graph(context: Context): MailGraph = holder.get(context)

    fun invalidate() = holder.invalidate()
}
