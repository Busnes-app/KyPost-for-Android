package org.kysecurity.mail

import android.content.Context
import org.kysecurity.mail.pgp.EnrollmentVault
import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.PgpBootstrapResult
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.pgp.RecipientKeyResult
import org.kysecurity.mail.pgp.isEnrolled
import org.kysecurity.mail.pgp.pgpComposeStateOf
import org.kysecurity.mail.pgp.probeEnrollment
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Flattens and dedupes case-insensitively; the first spelling the user typed wins. */
fun splitAddresses(vararg commaJoined: String): List<String> {
    val seen = mutableSetOf<String>()
    return commaJoined
        .flatMap { it.split(',') }
        .map { it.trim() }
        .filter { it.isNotEmpty() }
        .filter { seen.add(it.lowercase()) }
}

/** Nothing here decides whether to send: the relay's 409 is the gate, not this preflight. */
class ComposePgpController(
    private val pairingProvider: () -> PairingData?,
    private val bootstrapClient: PgpBootstrapClient,
    private val recipientKeyClient: RecipientKeyClient,
    private val enrollmentProbe: suspend () -> Boolean = { false },
) {

    /** Bootstrap is cached on success only; enrollment is re-probed. Couldn't-check hides all. */
    suspend fun composeState(): PgpComposeState {
        val bootstrap = bootstrap() ?: return pgpComposeStateOf(hasIdentity = null, protection = null)
        return pgpComposeStateOf(
            hasIdentity = bootstrap.hasIdentity,
            protection = bootstrap.protection,
            deviceEnrolled = enrollmentProbe(),
            accountAddress = bootstrap.accountAddress,
        )
    }

    internal suspend fun draftHandoffMode(): org.kysecurity.mail.pgp.DraftHandoffMode {
        val state = bootstrap() ?: return org.kysecurity.mail.pgp.DraftHandoffMode.REFUSE
        return org.kysecurity.mail.pgp.draftHandoffMode(
            state.hasIdentity, state.protection, enrollmentProbe(), state.accountAddress,
        )
    }

    /** The address every client-encrypted delivery's `From` must carry. Blank when unknown, which
     *  [pgpComposeStateOf] already degrades to the webmail handoff. */
    suspend fun accountAddress(): String = bootstrap()?.accountAddress.orEmpty()

    /** The cached bootstrap, or null when unpaired or the fetch failed. */
    private suspend fun bootstrap(): PgpBootstrapResult.Success? {
        cachedBootstrap?.let { return it }
        // pairingProvider() reads Keystore-backed prefs and does an AES unwrap: disk plus crypto.
        val pairing = withContext(Dispatchers.IO) { pairingProvider() }
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return null
        return when (val result = bootstrapClient.fetch(pairing.serverUrl, deviceId, deviceSecret)) {
            is PgpBootstrapResult.Success -> result.also { cachedBootstrap = it }
            is PgpBootstrapResult.Failed -> null
        }
    }

    /** A lower bound, never a promise: the send path also runs WKD and keyserver discovery. */
    suspend fun keylessRecipients(addresses: List<String>): List<String> {
        // Same off-main-thread rationale as composeState() above.
        val pairing = withContext(Dispatchers.IO) { pairingProvider() }
        val deviceId = pairing?.deviceId
        val deviceSecret = pairing?.deviceSecret
        if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return emptyList()
        return when (val result = recipientKeyClient.check(pairing.serverUrl, deviceId, deviceSecret, addresses)) {
            is RecipientKeyResult.Success -> result.keyless
            is RecipientKeyResult.Failed -> emptyList()
        }
    }

    companion object : ProcessScopedState {
        /** Process-scoped: an account switch does not restart the process, so it must be reset. */
        @Volatile
        private var cachedBootstrap: PgpBootstrapResult.Success? = null

        init {
            ProcessState.register(this)
        }

        override fun resetForNewSession() = resetSessionCache()

        fun resetSessionCache() {
            cachedBootstrap = null
        }

        fun from(context: Context): ComposePgpController = ComposePgpController(
            pairingProvider = { PushRuntime.graph(context).repository.pairingForAuthenticatedCall() },
            bootstrapClient = PgpBootstrapClient(callFactory = pinnedPairingCallFactory(context)),
            recipientKeyClient = RecipientKeyClient(callFactory = pinnedPairingCallFactory(context)),
            // Probes the Keystore, not our bookkeeping, so it stays honest across an OS key wipe.
            enrollmentProbe = {
                withContext(Dispatchers.IO) { probeEnrollment(EnrollmentVault(context)).isEnrolled() }
            },
        )
    }
}
