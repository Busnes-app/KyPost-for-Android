package org.kysecurity.mail.pgp

import android.content.Context
import org.kysecurity.mail.push.PushRuntime
import org.kysecurity.mail.push.pinnedPairingCallFactory

/** null means "couldn't check" — callers must not render it as "no identity". */
internal fun pgpIdentityFromMintResult(result: PgpQrTokenResult): Boolean? = when (result) {
    is PgpQrTokenResult.Success -> true
    is PgpQrTokenResult.NoIdentity -> false
    else -> null
}

/** `GET /api/pgp/identity` is web-session-only, so the QR mint doubles as the identity probe. */
suspend fun hasPgpIdentity(
    context: Context,
    client: PgpQrClient = PgpQrClient(callFactory = pinnedPairingCallFactory(context)),
): Boolean? {
    val pairing = PushRuntime.graph(context).repository.pairingForAuthenticatedCall()
    val deviceId = pairing?.deviceId
    val deviceSecret = pairing?.deviceSecret
    if (pairing == null || deviceId.isNullOrBlank() || deviceSecret.isNullOrBlank()) return null
    return pgpIdentityFromMintResult(client.mintToken(pairing.serverUrl, deviceId, deviceSecret))
}

/** Hashed locally from the bootstrap public key, never the response's `fingerprint` field. */
internal fun ownFingerprintFromBootstrap(result: PgpBootstrapResult): String? = when (result) {
    is PgpBootstrapResult.Success -> result.publicKey.takeIf { it.isNotBlank() }
        ?.let { PgpFingerprint.compute(it) }
    is PgpBootstrapResult.Failed -> null
}

internal sealed class OwnFingerprint {
    /** From this device's own private key: the only fingerprint the QR may carry. */
    data class Local(val fingerprint: String) : OwnFingerprint()

    /** The server's report, hashed locally but not tied to any key this device holds. */
    data class ServerReported(val fingerprint: String?) : OwnFingerprint()
}

/** The open vault's signer when there is one; the server is asked only when there is not. */
internal suspend fun ownFingerprint(serverReport: suspend () -> PgpBootstrapResult): OwnFingerprint =
    EnrollmentSession.withSigner { signer -> signer?.let { PgpFingerprint.of(it.publicKey) } }
        ?.let { OwnFingerprint.Local(it) }
        ?: OwnFingerprint.ServerReported(ownFingerprintFromBootstrap(serverReport()))
