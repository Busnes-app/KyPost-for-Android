package org.kysecurity.mail.push

import android.content.Context
import org.kysecurity.mail.SingletonGraph
import okhttp3.Call

class PushGraph(context: Context) {
    private val appContext = context.applicationContext

    /** The single [SecurePairingStore] for the process; it owns the pairing StateFlow. */
    val securePairingStore = SecurePairingStore(appContext)

    val repository = PushRepository(appContext, securePairingStore)

    /** The single [MfaChallengeTracker] for the process. */
    val mfaChallengeTracker = MfaChallengeTracker(appContext)

    // Shares one pinned-or-fallback factory; unpinned only before the first pairing. See [TlsPinState].
    private val pinnedOrFallbackCallFactory: Call.Factory = PinnedOrFallbackCallFactory(
        pinnedProvider = PinnedCallFactoryProvider(tlsPinProvider = { repository.currentTlsPin() }),
        pinStateProvider = { repository.tlsPinState() },
    )

    val pullCoordinator = PullSyncCoordinator(
        repository = repository,
        pullClient = PullNotificationClient(callFactory = pinnedOrFallbackCallFactory),
        // The same two exits a pushed message takes in the messaging services.
        notifier = { incoming ->
            when (incoming) {
                is IncomingPush.Mfa -> PushNotificationDispatcher.showMfaChallenge(appContext, incoming.payload)
                is IncomingPush.Mail -> PushNotificationDispatcher.show(appContext, incoming.payload)
            }
        },
        ensurePeriodic = { PullScheduler.ensurePeriodic(appContext) },
    )
    val syncCoordinator = PushSyncCoordinator(
        repository = repository,
        // The channel's own transport: Firebase on play/github, UnifiedPush on fdroid. This is
        // the single place the two builds diverge at runtime.
        fetchRegistrationCredential = { ChannelPush.registrationCredential(appContext, repository) },
        // First pairing pins to the link's `pin` when the relay published one, TOFU otherwise;
        // every resync afterward pins to the captured leaf.
        registrationClient = NativeRegistrationClient(callFactory = pinnedOrFallbackCallFactory),
        // A replacement that cannot prove the previous account's data is gone leaves rows no query
        // can attribute to an account. Erasing the device is the only state that is not "both".
        wipeOnIncompletePurge = { residue ->
            android.util.Log.e("PushGraph", "Wiping: account replacement could not purge $residue")
            org.kysecurity.mail.security.SecurityWipe.wipeAndResetApp(appContext)
        },
    )
    val mfaResponseClient = MfaResponseClient(callFactory = pinnedOrFallbackCallFactory)

    /** Its own factory purely for the hard call timeout — see [DEREGISTER_CALL_TIMEOUT_MS]. */
    val deregisterClient = DeregisterClient(
        callFactory = PinnedOrFallbackCallFactory(
            pinnedProvider = PinnedCallFactoryProvider(
                tlsPinProvider = { repository.currentTlsPin() },
                callTimeoutMillis = DEREGISTER_CALL_TIMEOUT_MS,
            ),
            pinStateProvider = { repository.tlsPinState() },
            fallback = org.kysecurity.mail.pairingHttpClient(
                posture = org.kysecurity.mail.PinPosture.TofuWindow,
                callTimeoutMillis = DEREGISTER_CALL_TIMEOUT_MS,
            ),
        ),
    )

    internal companion object {
        /** Internal, not private: [org.kysecurity.mail.security.SecurityWipe] reuses this ceiling. */
        const val DEREGISTER_CALL_TIMEOUT_MS = 3_000L
    }
}

object PushRuntime {
    private val holder = SingletonGraph(::PushGraph)

    fun graph(context: Context): PushGraph = holder.get(context)

    /** See [org.kysecurity.mail.SingletonGraph.invalidate] — used by
     *  [org.kysecurity.mail.security.AppRestart]. */
    fun invalidate() = holder.invalidate()
}

