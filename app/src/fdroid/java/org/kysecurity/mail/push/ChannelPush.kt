package org.kysecurity.mail.push

import android.content.Context
import kotlinx.coroutines.flow.first

/** UnifiedPush, for the `fdroid` channel, which ships no Google code at all.
 *
 *  Registration is a two-step dance rather than a fetch, and it cannot be collapsed into one:
 *  the endpoint is minted by the distributor and arrives asynchronously on
 *  [KyPostUnifiedPushService.onNewEndpoint], which persists it. So this reads what the connector
 *  has already produced, and returns null until it has produced something — which is why the
 *  pairing screen offers the distributor choice before the device is paired. */
object ChannelPush : ChannelPushTransport {

    /** Names the transport explicitly. Left unset, the server derives `fcm` from
     *  `platform: "android"` and then relays to an endpoint URL as though it were an FCM token —
     *  it reaches nothing, and the device is refused MFA challenges besides. The RFC 8291 keys
     *  ride along because a UnifiedPush device without them receives its notifications in the
     *  clear on a public broker, and the server excludes it from MFA for exactly that reason. */
    override suspend fun registrationCredential(
        context: Context,
        store: PushStore,
    ): PushRegistrationCredential? = store.state.first().unifiedPushCredential()

    /** The transport-neutral teardown in [PushRepository] already unregisters the distributor and
     *  deletes the connector's key material. There is no second transport with state of its own,
     *  so there is nothing here that can fail. */
    override suspend fun tearDown(context: Context): Boolean = true

    /** Nothing to fall back to. A build with no Firebase that "reverts to Firebase" on a
     *  UnifiedPush failure ends up paired, registered and permanently silent. */
    override val canReplaceUnifiedPush: Boolean = false
}
