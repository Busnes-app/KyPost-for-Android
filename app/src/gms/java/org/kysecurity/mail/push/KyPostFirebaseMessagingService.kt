package org.kysecurity.mail.push

import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import org.kysecurity.mail.security.SecurityWipe

private const val TAG = "KyPostFcm"

class KyPostFirebaseMessagingService : FirebaseMessagingService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    override fun onCreate() {
        super.onCreate()
        PushNotificationDispatcher.ensureChannel(this)
        PushNotificationDispatcher.ensureMfaChannel(this)
    }

    override fun onNewToken(token: String) {
        // Registration MINTS A NEW DEVICE SECRET — never re-arm a device whose wipe failed.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Refusing to re-register: a previous wipe was abandoned")
            return
        }
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            graph.syncCoordinator.syncProvidedToken(token)
        }
    }

    override fun onMessageReceived(message: RemoteMessage) {
        // Before parsing: an abandoned wipe usually leaves the pairing credential on disk.
        if (SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Dropping push: a previous wipe was abandoned with data still on this device")
            return
        }

        val graph = PushRuntime.graph(applicationContext)
        // Any delivery proves the transport is alive, which is what the pull heartbeat waits on.
        serviceScope.launch { graph.repository.markPushReceived(System.currentTimeMillis()) }

        when (val incoming = IncomingPushRouter.route(message.data)) {
            is IncomingPush.Mfa ->
                PushNotificationDispatcher.showMfaChallenge(applicationContext, incoming.payload)
            is IncomingPush.Mail -> {
                serviceScope.launch { graph.repository.appendPayload(incoming.payload) }
                PushNotificationDispatcher.show(applicationContext, incoming.payload)
            }
            null -> return
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        serviceScope.cancel()
    }
}

