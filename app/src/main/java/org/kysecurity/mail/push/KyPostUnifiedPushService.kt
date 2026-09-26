package org.kysecurity.mail.push

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch
import kotlinx.serialization.json.Json
import org.unifiedpush.android.connector.FailedReason
import org.unifiedpush.android.connector.PushService
import org.unifiedpush.android.connector.UnifiedPush
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage

/** UnifiedPush events. PushService is the current API; MessagingReceiver is deprecated. */
class KyPostUnifiedPushService : PushService() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val json = Json { ignoreUnknownKeys = true }

    override fun onCreate() {
        super.onCreate()
        // PushNotificationDispatcher.show() calls ensureChannel itself, which is why mail worked
        // here without this; showMfaChallenge does not, so an MFA challenge would have posted to
        // a channel that does not exist and shown nothing. KyPostFirebaseMessagingService has
        // done both since it was written.
        PushNotificationDispatcher.ensureChannel(this)
        PushNotificationDispatcher.ensureMfaChannel(this)
    }

    companion object {
        private const val TAG = "KyPostUnifiedPushService"
    }

    override fun onNewEndpoint(endpoint: PushEndpoint, instance: String) {
        // As in KyPostFirebaseMessagingService.onNewToken: this re-registers, and registration
        // mints a new device secret. An abandoned wipe must not have its credential renewed.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Refusing to re-register: a previous wipe was abandoned")
            return
        }
        val graph = PushRuntime.graph(applicationContext)
        serviceScope.launch {
            // WebPush (RFC 8291) keys; without them onMessage only ever sees ciphertext.
            graph.syncCoordinator.syncProvidedToken(
                endpoint.url,
                transport = PushTransport.UNIFIED_PUSH,
                p256dh = endpoint.pubKeySet?.pubKey,
                auth = endpoint.pubKeySet?.auth,
            )
        }
    }

    override fun onRegistrationFailed(reason: FailedReason, instance: String) {
        val graph = PushRuntime.graph(applicationContext)
        val message = unifiedPushFailureMessage(reason.toString(), ChannelPush.canReplaceUnifiedPush)

        if (!ChannelPush.canReplaceUnifiedPush) {
            // Keep the distributor selection. It is the only delivery route this build has, so
            // discarding it turns a retryable failure — the distributor being offline, a network
            // blip — into a state the user can only leave by re-pairing. And do not re-register:
            // there is no other transport to register on, so it would fail for a second reason
            // and overwrite the one that explains this.
            serviceScope.launch {
                graph.repository.updateSyncState(lastSyncAtEpochMs = null, syncError = message)
            }
            return
        }

        // Clear the stale distributor and fall back to FCM so the user isn't left with no delivery.
        UnifiedPush.removeDistributor(applicationContext)
        serviceScope.launch {
            graph.repository.updateSyncState(lastSyncAtEpochMs = null, syncError = message)
            graph.syncCoordinator.syncCurrentPairingToken()
        }
    }

    override fun onUnregistered(instance: String) {
        val graph = PushRuntime.graph(applicationContext)
        if (!ChannelPush.canReplaceUnifiedPush) {
            // Nothing to fall back to. Say so instead of silently re-registering on a transport
            // this build does not have: that call fails, and the pairing screen would show the
            // generic "unable to obtain a token" rather than the fact the user unregistered.
            serviceScope.launch {
                graph.repository.updateSyncState(
                    lastSyncAtEpochMs = null,
                    syncError = "No UnifiedPush distributor is selected, so notifications are stopped.",
                )
            }
            return
        }
        // Explicit unregistration (user switched distributor away, or picked "none"):
        // fall back to FCM so delivery keeps working without user intervention.
        serviceScope.launch {
            graph.syncCoordinator.syncCurrentPairingToken()
        }
    }

    override fun onMessage(message: PushMessage, instance: String) {
        // Same guard, same reason, as the FCM receive path: no sender or subject on the lock
        // screen of a device whose wipe could not finish.
        if (org.kysecurity.mail.security.SecurityWipe.blockedByAbandonedWipe(applicationContext)) {
            android.util.Log.e(TAG, "Dropping push: a previous wipe was abandoned with data still on this device")
            return
        }

        if (!message.decrypted) {
            // content is ciphertext, not JSON — usually a p256dh/auth mismatch with what we registered.
            android.util.Log.w(TAG, "Dropping UnifiedPush message: decryption failed")
            return
        }

        val graph = PushRuntime.graph(applicationContext)
        // After the decryption check on purpose: a key mismatch means nothing will ever be readable
        // on this channel, and the heartbeat polling for it is the recovery.
        serviceScope.launch { graph.repository.markPushReceived(System.currentTimeMillis()) }

        val text = String(message.content, Charsets.UTF_8)
        val data = runCatching {
            json.decodeFromString<Map<String, String>>(text)
        }.getOrNull() ?: run {
            android.util.Log.w(TAG, "Dropping UnifiedPush message: not a valid JSON string map")
            return
        }

        when (val incoming = IncomingPushRouter.route(data)) {
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
        serviceScope.cancel()
        super.onDestroy()
    }
}
