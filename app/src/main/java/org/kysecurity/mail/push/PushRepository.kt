package org.kysecurity.mail.push

import android.content.Context
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.emptyPreferences
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import org.kysecurity.mail.ScopedValue
import org.kysecurity.mail.security.AppLockStore
import org.kysecurity.mail.security.SecurityRuntime
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.catch
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.update
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.io.IOException

private val Context.pushDataStore by preferencesDataStore(name = "push_state")

private val KEY_LAST_SYNC_AT = longPreferencesKey("sync_last_at")
private val KEY_SYNC_ERROR = stringPreferencesKey("sync_error")
private val KEY_HISTORY_JSON = stringPreferencesKey("history_json")
private val KEY_DELIVERY_MODE = stringPreferencesKey("delivery_mode")
private val KEY_PULL_ENDPOINT = stringPreferencesKey("pull_endpoint")
private val KEY_PULL_CURSOR = longPreferencesKey("pull_cursor")
private val KEY_PULL_CURSOR_SUB = stringPreferencesKey("pull_cursor_sub")
private val KEY_TRANSPORT = stringPreferencesKey("transport")
private val KEY_UNIFIEDPUSH_ENDPOINT = stringPreferencesKey("unifiedpush_endpoint")
private val KEY_UNIFIEDPUSH_P256DH = stringPreferencesKey("unifiedpush_p256dh")
private val KEY_UNIFIEDPUSH_AUTH = stringPreferencesKey("unifiedpush_auth")

private const val HISTORY_LIMIT = 30

private const val TAG = "PushRepository"

class PushRepository(
    private val context: Context,
    // Injected: PushGraph owns the single instance that holds the pairing StateFlow.
    private val securePairingStore: SecurePairingStore = SecurePairingStore(context),
) : PushStore {
    private val json = Json { ignoreUnknownKeys = true }
    private val hostileLocationSettings = SecurityRuntime.graph(context).hostileLocationSettings
    private val pullCursorValue = ScopedValue(
        dataStore = context.pushDataStore,
        scopeKey = KEY_PULL_CURSOR_SUB,
        valueKey = KEY_PULL_CURSOR,
    )

    /** Push history while Hostile Location Protection is on: nothing may touch disk. */
    private val inMemoryHistory = MutableStateFlow<List<PushPayload>>(emptyList())

    override val state: Flow<PushState> = combine(
        context.pushDataStore.data.catch { ex ->
            if (ex is IOException) emit(emptyPreferences()) else throw ex
        },
        securePairingStore.pairing,
        inMemoryHistory,
    ) { prefs, pairing, volatileHistory -> toState(prefs, pairing, volatileHistory) }

    /** Whether a pairing exists right now, read straight from the store — for cold-path callers. */
    fun isPairedNow(): Boolean = securePairingStore.pairing.value != null

    override fun pairingForAuthenticatedCall(): PairingData? =
        securePairingStore.pairingSnapshot(SecurityRuntime.graph(context).appLockManager.cachedCredentialKeys())

    /** For [MfaApprovalActivity]: the app is legitimately still locked when the decision is sent. */
    fun pairingForAuthenticatedCall(keys: org.kysecurity.mail.security.CredentialKeys?): PairingData? =
        securePairingStore.pairingSnapshot(keys)

    /** The TOFU TLS pin with its host, or null. Read fresh — it changes on re-pairing. */
    override fun currentTlsPin(): TlsPin? = securePairingStore.currentTlsPin()

    /** See [SecurePairingStore.tlsPinState] — distinguishes "never pinned" from "pin lost". */
    fun tlsPinState(): TlsPinState = securePairingStore.tlsPinState()

    /** See [SecurePairingStore.tlsPinIsLeafOnly] — false means a legacy whole-chain set is stored. */
    override fun tlsPinIsLeafOnly(): Boolean = securePairingStore.tlsPinIsLeafOnly()

    /** See [SecurePairingStore.reconnectExpectation] — whose data survived a credential-only reset. */
    override fun reconnectExpectation(): ReconnectExpectation? = securePairingStore.reconnectExpectation()

    /** Whether pairing [pairing] would activate a different account than the one whose data is on
     *  this device — the dialog wording must match what [PushSyncCoordinator.attemptPairing] does.
     *  Read from the store, not `state`: the confirmation runs on the cold path. */
    fun replacesAnotherAccount(pairing: PairingData): Boolean =
        isAccountReplacement(pairing, securePairingStore.pairing.value, reconnectExpectation())

    /** Persist a TLS pin observed on a just-succeeded call: the TOFU capture in
     *  [PushSyncCoordinator.attemptPairing], and the one-way narrowing in
     *  [PushSyncCoordinator.narrowLegacyTlsPin]. */
    override suspend fun saveTlsPin(pin: TlsPin) = securePairingStore.saveTlsPin(pin)

    /** True when the stored `deviceSecret` still needs wrapping (or re-wrapping) under the current
     *  credential-key scheme; see [SecurePairingStore.needsCredentialRewrap]. */
    fun needsCredentialRewrap(): Boolean = securePairingStore.needsCredentialRewrap()

    /** Captured before the network call and reused after: the app can lock in between. */
    sealed class PairingCredentialState {
        /** The credential gate is off: secrets are stored as they arrive. */
        object NotGated : PairingCredentialState()

        /** Not a `data class`: identity `equals`/`hashCode` over [salt] behind a promise of
         *  structural equality. Only ever matched with `is`. Enforced by `SourceRulesTest`. */
        class Available(
            val keys: org.kysecurity.mail.security.CredentialKeys,
            val salt: ByteArray,
        ) : PairingCredentialState()

        /** The gate is on and no PIN-derived key exists here — nothing may be wrapped, and nothing
         *  that is already stored may be replaced. */
        object Unavailable : PairingCredentialState()
    }

    /** Callers about to mint a secret must take this first and hand it back to [savePairing]. */
    override fun currentCredentialState(): PairingCredentialState {
        val securityGraph = SecurityRuntime.graph(context)
        if (!securityGraph.appLockStore.isCredentialPinGateEnabled()) return PairingCredentialState.NotGated
        val keys = securityGraph.appLockManager.cachedCredentialKeys() ?: return PairingCredentialState.Unavailable
        val salt = securityGraph.appLockStore.credentialSalt() ?: return PairingCredentialState.Unavailable
        return PairingCredentialState.Available(keys, salt)
    }

    /** Saves pairing data, wrapping `deviceSecret` when the credential gate is on. */
    override suspend fun savePairing(
        pairing: PairingData,
        credentialState: PairingCredentialState,
    ) {
        when (credentialState) {
            is PairingCredentialState.Available ->
                securePairingStore.savePairing(
                    pairing,
                    gateEnabled = true,
                    credentialKeys = credentialState.keys,
                    credentialSalt = credentialState.salt,
                )
            is PairingCredentialState.Unavailable -> {
                if (!pairing.deviceSecret.isNullOrBlank()) {
                    android.util.Log.e(
                        TAG,
                        "Refusing to store a device secret with the credential gate on and no PIN-derived key; " +
                            "the caller should have taken currentCredentialState() before registering",
                    )
                }
                securePairingStore.savePairing(pairing, SecretWrite.Preserve)
            }
            is PairingCredentialState.NotGated ->
                securePairingStore.savePairing(pairing, gateEnabled = false)
        }
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_SYNC_ERROR)
        }
    }

    /** Drops everything scoped to the account we are leaving; no table carries a subscriber column.
     *
     *  Returns the stores that could NOT be shown to be gone. Every failure below used to be a
     *  `Log.e` the caller could not see, so an account replacement whose purge failed activated
     *  the new account over the old one's mail. Naming the survivors is what lets
     *  [PushSyncCoordinator] refuse. */
    private suspend fun purgeAccountScopedData(): List<String> {
        val residue = mutableListOf<String>()

        /** Runs [body] and records [name] if it throws or reports incomplete. */
        suspend fun step(name: String, body: suspend () -> Boolean) {
            val ok = runCatching { body() }
                .onFailure { android.util.Log.e(TAG, "Failed to purge $name", it) }
                .getOrDefault(false)
            if (!ok) residue += name
        }

        // The OS contact rows go FIRST, while the link table that indexes them still exists.
        // DeviceContactPurge, not the graph: building that graph rebuilds the database during a wipe.
        step("deviceContactRows") {
            org.kysecurity.mail.contacts.device.DeviceContactPurge.deleteSyncedRows(context) >= 0
        }
        step("deviceContactAccount") {
            val accounts = org.kysecurity.mail.contacts.device.DeviceContactAccountManager(context)
            !accounts.accountExists() || accounts.removeAccountBlocking()
        }
        step("deviceContactWorker") {
            org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler.cancelPeriodic(context)
            true
        }

        step("database") {
            // peek, not graph: building one during a wipe recreates the database, disk-backed.
            val db = org.kysecurity.mail.data.DataRuntime.peekGraph()?.database
            if (db != null) {
                db.emailDao().clearAll()
                db.contactDao().clearAll()
                db.pendingContactChangeDao().clearAll()
                db.groupDao().clearAll()
                db.groupLinkDao().clearAll()
                db.deviceContactLinkDao().deleteAll()
                // The contact-sync cursor lives here now; without this a re-pair resumes from the old cursor.
                db.contactSyncStateDao().clearAll()
            } else {
                // No graph in this process does NOT mean no data: the encrypted file is still on
                // disk, and treating the null as "already purged" is how one account's cached mail
                // reached the next one. Nothing holds the file open, so deleting it is both safe
                // and the only proof available. Throws if the file survives.
                org.kysecurity.mail.security.SecurityWipe.closeAndDeleteDatabase(context)
            }
            true
        }

        // Device-contact sync gates only on its own toggle and Hostile Location Protection, never
        // on having a pairing, so it has to be switched off explicitly here.
        step("deviceContactSyncSetting") {
            org.kysecurity.mail.contacts.device.DeviceContactSyncSettings(context).setEnabled(false)
            true
        }
        step("keywordSettings") {
            context.deleteSharedPreferences(org.kysecurity.mail.KeywordSettings.PREFS_NAME)
        }
        // Scoping makes a stale value unreadable, not absent — these files must actually be deleted.
        // contacts_state is legacy: kept in this list so older installs do not keep the old file.
        listOf("mail_sync_state", "contacts_state").forEach { name ->
            step("datastore/$name") {
                val file = java.io.File(context.filesDir, "datastore/$name.preferences_pb")
                !file.exists() || file.delete()
            }
        }
        // Every process-static holder at once via the registry, not by name — enumeration missed one.
        step("enrollment") { org.kysecurity.mail.pgp.EnrollmentTeardown.destroy(context).isEmpty() }
        // The teardown above asks the worker to tell the server "not enrolled". With the pairing
        // gone there is no device row to correct, and the marker must not speak for the next one.
        step("enrollmentTeardownMarker") { org.kysecurity.mail.pgp.EnrollmentVault(context).clearTeardownReport() }
        step("processMemory") { org.kysecurity.mail.InMemoryPlaintext.clearAll().isEmpty() }

        if (residue.isNotEmpty()) {
            android.util.Log.e(TAG, "Account-scoped purge left $residue behind")
        }
        return residue
    }

    /** Drops pairing proof and the TOFU pin, KEEPING account-scoped data.
     *
     *  Recovering from a rotated certificate or a stranded device secret is not a change of
     *  account, and must not cost the user their mail. [clearPairing] stays the destructive one,
     *  for a deliberate unpair and for [PushSyncCoordinator.attemptPairing]'s genuine
     *  account-replacement branch. Clearing the pin reopens the TOFU window so the next pairing
     *  can capture a fresh chain.
     *
     *  It also records which account the kept data belongs to. Without that marker the next
     *  [PushSyncCoordinator.attemptPairing] saw no pairing, concluded there was nothing to replace,
     *  and activated a DIFFERENT account over this one's mail, contacts, PGP vault and pending
     *  contact changes — none of which carries a subscriber column. */
    suspend fun resetPairingCredential() {
        securePairingStore.clearPairing(rememberForReconnect = true)
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_SYNC_ERROR)
            prefs.remove(KEY_LAST_SYNC_AT)
            // Registration state that belongs to the credential being reset, not to the account.
            prefs.remove(KEY_TRANSPORT)
            prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT)
            prefs.remove(KEY_UNIFIEDPUSH_P256DH)
            prefs.remove(KEY_UNIFIEDPUSH_AUTH)
        }
    }

    override suspend fun clearPairing(): List<String> {
        val residue = purgeAccountScopedData()
        securePairingStore.clearPairing()
        inMemoryHistory.value = emptyList()
        context.pushDataStore.edit { prefs ->
            prefs.remove(KEY_LAST_SYNC_AT)
            prefs.remove(KEY_SYNC_ERROR)
            prefs.remove(KEY_HISTORY_JSON)
            prefs.remove(KEY_DELIVERY_MODE)
            prefs.remove(KEY_PULL_ENDPOINT)
            prefs.remove(KEY_PULL_CURSOR)
            prefs.remove(KEY_PULL_CURSOR_SUB)
            prefs.remove(KEY_TRANSPORT)
            prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT)
            prefs.remove(KEY_UNIFIEDPUSH_P256DH)
            prefs.remove(KEY_UNIFIEDPUSH_AUTH)
        }
        return residue
    }

    /** Best-effort deregister then unconditional clear; SecurityWipe passes a pre-captured pairing.
     *
     *  Returns [clearPairing]'s residue as well as the network result. Dropping it here was the
     *  hole: pairing proof is gone either way, so the next [PushSyncCoordinator.attemptPairing]
     *  sees no existing pairing, skips its replacement purge, and the new account inherits
     *  whatever survived. No table carries a subscriber column, so survivors are readable by
     *  whoever pairs next -- the caller must escalate a non-empty residue to a full wipe. */
    suspend fun unpairDevice(
        deregisterClient: DeregisterClient,
        pairing: PairingData? = pairingForAuthenticatedCall(),
    ): UnpairOutcome {
        val networkResult = if (pairing != null) {
            deregisterClient.deregister(pairing)
        } else {
            DeregisterResult.Error("Device is not paired")
        }
        tearDownPushTransport()
        val residue = clearPairing()
        PullScheduler.cancelPeriodic(context)
        return UnpairOutcome(networkResult, residue)
    }

    /** Severs the delivery channel itself. Not called from [PushSyncCoordinator]'s replacement path. */
    private suspend fun tearDownPushTransport() {
        runCatching {
            context.getSystemService(android.app.NotificationManager::class.java)?.cancelAll()
        }
        // Unregister before deleting the connector's state, or the device stays subscribed.
        runCatching { UnifiedPushRegistrar.unregister(context) }
        // Holds the WebPush ECDH private key and auth secret.
        runCatching { context.deleteDatabase("unifiedpush-connector") }
        // UnifiedPush.unregister keeps the distributor selection on purpose so a later re-register
        // reuses it; after an unpair that record should not outlive the pairing.
        runCatching { context.deleteSharedPreferences("unifiedpush.connector") }
        // Whatever this channel's own transport keeps. On a Firebase build that is the messaging
        // token and the installation Fid; on the Firebase-free one there is nothing left to do.
        ChannelPush.tearDown(context)
    }

    /** Persist the authoritative delivery mode and (derived or server-provided) pull endpoint. */
    override suspend fun updateDelivery(mode: DeliveryMode, pullEndpoint: String?) {
        context.pushDataStore.edit { prefs ->
            prefs[KEY_DELIVERY_MODE] = mode.wire
            if (pullEndpoint.isNullOrBlank()) prefs.remove(KEY_PULL_ENDPOINT) else prefs[KEY_PULL_ENDPOINT] = pullEndpoint
        }
    }

    /** Persist the transport the server confirmed for the last successful registration. */
    override suspend fun updateTransport(transport: PushTransport?) {
        context.pushDataStore.edit { prefs ->
            if (transport == null) prefs.remove(KEY_TRANSPORT) else prefs[KEY_TRANSPORT] = transport.wire
        }
    }

    /** Persisted so a resync can resend them; they only ever arrive via onNewEndpoint. Null clears. */
    override suspend fun updateUnifiedPushRegistration(endpoint: String?, p256dh: String?, auth: String?) {
        context.pushDataStore.edit { prefs ->
            if (endpoint.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_ENDPOINT) else prefs[KEY_UNIFIEDPUSH_ENDPOINT] = endpoint
            if (p256dh.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_P256DH) else prefs[KEY_UNIFIEDPUSH_P256DH] = p256dh
            if (auth.isNullOrBlank()) prefs.remove(KEY_UNIFIEDPUSH_AUTH) else prefs[KEY_UNIFIEDPUSH_AUTH] = auth
        }
    }

    /** The durable pull cursor for [subscriberId], scoped so a new subscriber starts clean. */
    override suspend fun pullCursor(subscriberId: String): Long = pullCursorValue.get(subscriberId) ?: 0L

    /** Advance the cursor to max(existing, [cursor]); resets when the subscriber changes. */
    override suspend fun advancePullCursor(subscriberId: String, cursor: Long) {
        pullCursorValue.update(subscriberId) { current -> maxOf(current ?: 0L, cursor) }
    }

    override suspend fun updateSyncState(lastSyncAtEpochMs: Long?, syncError: String?) {
        context.pushDataStore.edit { prefs ->
            if (lastSyncAtEpochMs == null) prefs.remove(KEY_LAST_SYNC_AT) else prefs[KEY_LAST_SYNC_AT] = lastSyncAtEpochMs
            if (syncError.isNullOrBlank()) prefs.remove(KEY_SYNC_ERROR) else prefs[KEY_SYNC_ERROR] = syncError
        }
    }

    override suspend fun appendPayload(payload: PushPayload) {
        if (hostileLocationSettings.isEnabled()) {
            inMemoryHistory.update { current -> (listOf(payload) + current).distinctBy { it.messageId }.take(HISTORY_LIMIT) }
            return
        }
        context.pushDataStore.edit { prefs ->
            val current = decodeHistory(prefs[KEY_HISTORY_JSON])
            val updated = (listOf(payload) + current)
                .distinctBy { it.messageId }
                .take(HISTORY_LIMIT)
            prefs[KEY_HISTORY_JSON] = json.encodeToString(updated)
        }
    }

    private fun toState(prefs: Preferences, pairing: PairingData?, volatileHistory: List<PushPayload>): PushState {
        val history = if (hostileLocationSettings.isEnabled()) volatileHistory else decodeHistory(prefs[KEY_HISTORY_JSON])
        val pullEndpoint = prefs[KEY_PULL_ENDPOINT]
            ?: pairing?.serverUrl?.let { resolvePullEndpoint(it, null) }
        return PushState(
            pairing = pairing,
            lastTokenSyncAtEpochMs = prefs[KEY_LAST_SYNC_AT],
            syncError = prefs[KEY_SYNC_ERROR],
            history = history,
            latestPayload = history.firstOrNull(),
            deliveryMode = DeliveryMode.fromWire(prefs[KEY_DELIVERY_MODE]),
            pullEndpoint = pullEndpoint,
            transport = PushTransport.fromWire(prefs[KEY_TRANSPORT]),
            unifiedPushEndpoint = prefs[KEY_UNIFIEDPUSH_ENDPOINT],
            unifiedPushP256dh = prefs[KEY_UNIFIEDPUSH_P256DH],
            unifiedPushAuth = prefs[KEY_UNIFIEDPUSH_AUTH],
        )
    }

    private fun decodeHistory(value: String?): List<PushPayload> {
        if (value.isNullOrBlank()) return emptyList()
        return runCatching { json.decodeFromString<List<PushPayload>>(value) }
            .onFailure { android.util.Log.w(TAG, "Dropping unreadable push history", it) }
            .getOrDefault(emptyList())
    }
}

data class PushState(
    val pairing: PairingData?,
    val lastTokenSyncAtEpochMs: Long?,
    val syncError: String?,
    val latestPayload: PushPayload?,
    val history: List<PushPayload>,
    val deliveryMode: DeliveryMode = DeliveryMode.PUSH,
    val pullEndpoint: String? = null,
    val transport: PushTransport? = null,
    val unifiedPushEndpoint: String? = null,
    val unifiedPushP256dh: String? = null,
    val unifiedPushAuth: String? = null,
)
