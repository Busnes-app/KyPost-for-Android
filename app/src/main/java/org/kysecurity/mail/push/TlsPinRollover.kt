package org.kysecurity.mail.push

import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Interceptor
import okhttp3.Request
import okhttp3.Response
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.security.SpkiPinner
import java.util.Base64
import javax.net.ssl.SSLPeerUnverifiedException
import kotlin.math.abs

/** Domain separation; KyPost-Server `api/relay_identity.go` signs the same string. */
private const val STATEMENT_CONTEXT = "kypost-tls-pin/1"
private const val TLS_PIN_PATH = "/api/notifications/native/tls-pin"

/** How far a statement's `issuedAt` may sit from this device's clock. It bounds the replay of a
 *  statement for a retired leaf to someone who also holds that leaf's key and a valid certificate. */
internal const val STATEMENT_MAX_SKEW_SECONDS = 24 * 60 * 60L

/** The relay's Ed25519 public key as sent on the wire, or null unless it is exactly 32 bytes. */
internal fun relayIdentityKeyOrNull(raw: String?): String? =
    raw?.takeIf { runCatching { Base64.getDecoder().decode(it).size == 32 }.getOrDefault(false) }

/** Ed25519 over `kypost-tls-pin/1\n<host>\n<pin>\n<issuedAt>`. BouncyCastle, not JCA: Android has
 *  no EdDSA before API 33 and minSdk is 31. */
internal fun verifyTlsPinStatement(publicKey: String, host: String, pin: String, issuedAt: Long, signature: String): Boolean =
    runCatching {
        val message = "$STATEMENT_CONTEXT\n$host\n$pin\n$issuedAt".toByteArray(Charsets.UTF_8)
        Ed25519Signer().run {
            init(false, Ed25519PublicKeyParameters(Base64.getDecoder().decode(publicKey), 0))
            update(message, 0, message.size)
            verifySignature(Base64.getDecoder().decode(signature))
        }
    }.getOrDefault(false)

@Serializable
private data class TlsPinStatement(
    @SerialName("host") val host: String,
    @SerialName("pin") val pin: String,
    @SerialName("issuedAt") val issuedAt: Long,
    @SerialName("signature") val signature: String,
)

/** Learn a replay floor only from a signed statement for the leaf just authenticated.
 * Failure leaves rollover disabled; ordinary pinned requests and manual reconnect still work. */
internal suspend fun captureTlsPinBaseline(
    pin: TlsPin,
    serverUrl: String,
    fetcher: Call.Factory? = null,
    nowEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
): TlsPin {
    val key = pin.relayIdentityKey ?: return pin
    val url = pairingEndpoint(serverUrl, TLS_PIN_PATH) ?: return pin
    if (!url.host.equals(pin.host, ignoreCase = true)) return pin
    return withContext(Dispatchers.IO) {
        val client = fetcher ?: pairingHttpClient(PinPosture.Pinned(pin.host, pin.spkiSha256))
        val floor = client.executeSync(Request.Builder().url(url).get().build()) { response ->
            if (response.code != 200) return@executeSync null
            val leaf = response.handshake?.peerCertificates?.firstOrNull() ?: return@executeSync null
            val body = response.body?.string() ?: return@executeSync null
            val statement = Json { ignoreUnknownKeys = true }.decodeFromString<TlsPinStatement>(body)
            val observed = SpkiPinner.pinFor(leaf)
            if (observed !in pin.spkiSha256 || statement.pin != observed ||
                !statement.host.equals(pin.host, ignoreCase = true) || statement.issuedAt <= 0 ||
                abs(nowEpochSeconds() - statement.issuedAt) > STATEMENT_MAX_SKEW_SECONDS ||
                !verifyTlsPinStatement(key, statement.host, statement.pin, statement.issuedAt, statement.signature)
            ) return@executeSync null
            statement.issuedAt
        }.getOrNull()
        if (floor == null) pin else pin.copy(statementIssuedAt = maxOf(pin.statementIssuedAt, floor))
    }
}

/** Signed TLS pin rollover: how a paired device survives its relay's certificate renewal.
 *
 *  The pin names one leaf, so a renewal with a new key fails every pinned call. On that failure
 *  this fetches the relay's signed statement over plain system trust, sending NO credential, and
 *  replaces the pin only when [TlsPin.relayIdentityKey] signed the exact leaf this fetch observed,
 *  for the pinned host, recently. An interceptor holding a locally trusted CA presents its own
 *  leaf, which the relay never signs; relaying the real statement fails the observed-leaf check.
 *  Without a key (older server, or never resynced since) nothing changes: a pairing link or
 *  "Reconnect" remain the recovery. */
class TlsPinRollover(
    private val currentPin: () -> TlsPin?,
    /** Compare-and-swap: writes the new pin only if the expected one is still stored. */
    private val replacePin: suspend (expected: TlsPin, new: TlsPin) -> Boolean,
    private val serverUrl: () -> String?,
    // Unpinned on purpose, and it carries no credential: see the class comment.
    private val fetcher: Call.Factory = pairingHttpClient(PinPosture.TofuWindow),
    private val nowEpochSeconds: () -> Long = { System.currentTimeMillis() / 1000 },
) {
    private val json = Json { ignoreUnknownKeys = true }

    /** Blocking. True when a call refused under [failed] is worth retrying: the pin was replaced,
     *  here or by a concurrent caller. Serialized so one renewal costs one fetch. */
    @Synchronized
    fun roll(failed: TlsPin): Boolean {
        val stored = currentPin() ?: return false
        if (stored != failed) return stored.host.equals(failed.host, ignoreCase = true)
        val key = stored.relayIdentityKey ?: return false
        if (stored.statementIssuedAt <= 0) return false
        val url = serverUrl()?.let { pairingEndpoint(it, TLS_PIN_PATH) } ?: return false
        if (!url.host.equals(stored.host, ignoreCase = true)) return false
        val (statement, observed) = fetcher.executeSync(Request.Builder().url(url).get().build()) { response ->
            if (response.code != 200) return@executeSync null
            val leaf = response.handshake?.peerCertificates?.firstOrNull() ?: return@executeSync null
            val body = response.body?.string() ?: return@executeSync null
            json.decodeFromString<TlsPinStatement>(body) to SpkiPinner.pinFor(leaf)
        }.getOrNull() ?: return false
        val valid = statement.pin == observed &&
            statement.host.equals(stored.host, ignoreCase = true) &&
            abs(nowEpochSeconds() - statement.issuedAt) <= STATEMENT_MAX_SKEW_SECONDS &&
            // Strictly newer than the rollover that installed this pin: a statement for a retired
            // leaf, replayed by someone holding that leaf's key, is always older.
            statement.issuedAt > stored.statementIssuedAt &&
            observed !in stored.spkiSha256 &&
            verifyTlsPinStatement(key, statement.host, statement.pin, statement.issuedAt, statement.signature)
        if (!valid) return false
        val replaced = runBlocking { replacePin(stored, TlsPin(stored.host, setOf(observed), key, statement.issuedAt)) }
        // Lost the race to a re-pair or unpair: the caller retries only if the pin is the same host.
        return replaced || currentPin()?.host.equals(stored.host, ignoreCase = true)
    }
}

/** Marks the one retry a rollover allows, so a relay alternating certificates cannot loop us. */
private object RolledOver

/** On the pinned client only: a pin failure asks [rollover] for a verified new leaf, then retries
 *  once through [provider], which rebuilds the client for the replaced pin. */
internal class TlsPinRolloverInterceptor(
    private val pin: TlsPin,
    private val rollover: TlsPinRollover,
    private val provider: () -> Pair<TlsPin, Call.Factory>?,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        try {
            return chain.proceed(request)
        } catch (e: SSLPeerUnverifiedException) {
            if (request.tag(RolledOver::class.java) != null || !rollover.roll(pin)) throw e
            val (next, client) = provider() ?: throw e
            if (next == pin || !request.url.host.equals(next.host, ignoreCase = true)) throw e
            return client.newCall(request.newBuilder().tag(RolledOver::class.java, RolledOver).build()).execute()
        }
    }
}
