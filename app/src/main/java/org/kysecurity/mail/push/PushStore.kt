package org.kysecurity.mail.push

import kotlinx.coroutines.flow.Flow

/** Everything the sync coordinators touch, as an interface.
 *
 *  The seam exists because the rules worth testing in [PushSyncCoordinator] and
 *  [PullSyncCoordinator] are ORDERING rules — nothing is destroyed before the replacement is
 *  proven, no two registrations persist at once — and a rule about ordering can only be tested by
 *  observing the order. [PushRepository] needs a real Android `Context`, DataStore and Keystore to
 *  exist at all, so the coordinators would otherwise be reachable only from an instrumented test,
 *  which is exactly where concurrency bugs go undetected. */
interface PushStore {
    val state: Flow<PushState>

    fun pairingForAuthenticatedCall(): PairingData?
    fun currentCredentialState(): PushRepository.PairingCredentialState
    fun currentTlsPin(): TlsPin?
    fun tlsPinIsLeafOnly(): Boolean

    /** The account a credential-only reconnect kept data for, or null. See [ReconnectExpectation]. */
    fun reconnectExpectation(): ReconnectExpectation?

    /** The default is declared HERE, not on the override: Kotlin resolves default arguments from
     *  the declaring member, and an override may not restate them. */
    suspend fun savePairing(
        pairing: PairingData,
        credentialState: PushRepository.PairingCredentialState = currentCredentialState(),
    )
    suspend fun saveTlsPin(pin: TlsPin)

    /** Purges every account-scoped store, then drops the pairing proof and the TOFU pin.
     *
     *  Returns the stores that could NOT be shown to be gone, empty when the purge was complete.
     *  A caller about to activate a DIFFERENT account must treat a non-empty result as a refusal:
     *  no table in this database carries a subscriber column, so data that survives is data the
     *  next account can read. */
    suspend fun clearPairing(): List<String>

    suspend fun updateDelivery(mode: DeliveryMode, pullEndpoint: String?)
    suspend fun updateTransport(transport: PushTransport?)
    suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?)
    suspend fun updateSyncState(lastSyncAtEpochMs: Long?, syncError: String?)
    /** A push arrived over the transport; resets the heartbeat's quiet clock. */
    suspend fun markPushReceived(nowEpochMs: Long)

    suspend fun pullCursor(subscriberId: String): Long
    suspend fun advancePullCursor(subscriberId: String, cursor: Long)
    /** Adds to history; false when [PushPayload.messageId] was already there. */
    suspend fun appendPayload(payload: PushPayload): Boolean
}
