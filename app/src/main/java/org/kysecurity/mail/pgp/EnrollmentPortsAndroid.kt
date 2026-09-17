package org.kysecurity.mail.pgp

import android.content.Context
import android.os.SystemClock
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext

/** [EnrollmentKeyStore] behind the port, so the ceremony's cleanup rule is testable on the JVM. */
internal object AndroidEnrollmentKeys : EnrollmentKeys {
    override fun newKeyPair(): Boolean = EnrollmentKeyStore.newKeyPair()
    override fun rawPublicKey(): ByteArray? = EnrollmentKeyStore.rawPublicKey()
    override fun encodedPublicKey(): String? = EnrollmentKeyStore.encodedPublicKey()
    override fun sharedSecret(epk: ByteArray): ByteArray? = EnrollmentKeyStore.sharedSecret(epk)
    override fun deleteKeyPair(): Boolean = EnrollmentKeyStore.deleteKeyPair()
}

/** Identity from one bootstrap call. The fingerprint is hashed from the key bytes, not a field. */
internal class AndroidIdentitySource(context: Context) : IdentitySource {
    private val appContext = context.applicationContext

    // withContext(IO) covers the whole body: the ceremony runs on Dispatchers.Main.immediate.
    override suspend fun check(): IdentityCheck = withContext(Dispatchers.IO) {
        val pairing = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) {
            // Not "no identity". The credential may simply be gated and the app currently locked.
            return@withContext IdentityCheck.CouldNotCheck
        }

        // The pinned factory, not PgpBootstrapClient's unpinned default. This request carries the
        // device bearer credential, like every other credentialed call in this app.
        val client = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(appContext))
        identityCheckFrom(client.fetch(pairing.serverUrl, deviceId, deviceSecret))
    }
}

/** The pure "degrade, never guess" mapping from a bootstrap response to an [IdentityCheck]. */
internal fun identityCheckFrom(result: PgpBootstrapResult): IdentityCheck = when (result) {
    is PgpBootstrapResult.Failed -> IdentityCheck.CouldNotCheck
    is PgpBootstrapResult.Success -> when {
        !result.hasIdentity -> IdentityCheck.NoIdentity
        result.protection == PROTECTION_CLIENT ->
            ownFingerprintFromBootstrap(result)
                ?.let { IdentityCheck.ClientProtected(it) }
            // An identity whose key will not parse is not an identity this device can bind
            // an AAD to. Reporting it as "could not check" rather than "no identity" keeps
            // the user's own key from being described as absent.
                ?: IdentityCheck.CouldNotCheck
        result.protection == PROTECTION_SERVER -> IdentityCheck.ServerHeld
        // Degrade, never guess — the same rule pgpComposeStateOf follows. Guessing "client"
        // here starts a ceremony that can only end at a failed GCM open, which is this
        // feature's one alarm.
        else -> IdentityCheck.CouldNotCheck
    }
}

/** The three enrollment calls, with the pairing read at call time rather than captured. */
internal class AndroidEnrollmentTransport(context: Context) : EnrollmentTransport {
    private val appContext = context.applicationContext

    // callFactory has no default on EnrollmentClients precisely so pinning cannot be forgotten.
    private val clients = EnrollmentClients(callFactory = pinnedPairingCallFactory(appContext))

    /** Blocking — never call from the main thread; every override below wraps it in Dispatchers.IO. */
    private fun pairing() = PushRuntime.graph(appContext).repository.pairingForAuthenticatedCall()
        ?.takeIf { !it.deviceId.isNullOrBlank() && !it.deviceSecret.isNullOrBlank() }

    override suspend fun deviceId(): String? = withContext(Dispatchers.IO) { pairing()?.deviceId }

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult =
        withContext(Dispatchers.IO) {
            val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
            clients.publishKey(p.serverUrl, p.deviceId!!, p.deviceSecret!!, encodedPublicKey)
        }

    override suspend fun fetchEnvelope(): EnrollmentCallResult = withContext(Dispatchers.IO) {
        val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
        clients.fetchEnvelope(p.serverUrl, p.deviceId!!, p.deviceSecret!!)
    }

    override suspend fun report(report: EnrollmentReport): EnrollmentCallResult =
        withContext(Dispatchers.IO) {
            val p = pairing() ?: return@withContext EnrollmentCallResult.Unauthorized
            clients.reportState(p.serverUrl, p.deviceId!!, p.deviceSecret!!, report)
        }

    override fun enqueueDurableReport() = EnrollmentStateWorker.enqueue(appContext)
}

/** isDeviceSecure, not [EnrollmentVault.ensureKey]: that mutates and can destroy an enrollment. */
internal fun hasSecureLockScreen(context: Context): Boolean =
    context.getSystemService(android.app.KeyguardManager::class.java)?.isDeviceSecure == true

/** Wall clock for the bucket (it must match the browser's), monotonic for the poll deadline. */
internal object SystemEnrollmentClock : EnrollmentClock {
    override fun epochSeconds(): Long = System.currentTimeMillis() / 1_000
    override fun elapsedRealtimeMs(): Long = SystemClock.elapsedRealtime()
    override suspend fun sleep(millis: Long) = delay(millis)
}

/** `DataRuntime.graph` is resolved inside the block: building it opens the database mid-wipe. */
internal class RoomDecryptedMailCache(private val appContext: Context) : DecryptedMailCache {
    override suspend fun clearServerDecryptedBodies(): Int = withContext(Dispatchers.IO) {
        DataRuntime.graph(appContext).database.emailDao().clearServerDecryptedBodies()
    }
}
