package org.kysecurity.mail.push

import android.os.Build
import org.kysecurity.mail.APP_VERSION
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.security.SpkiPinner
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

@Serializable
data class NativeRegistrationRequest(
    @SerialName("subscriberId") val subscriberId: String,
    @SerialName("pairingToken") val pairingToken: String,
    @SerialName("deviceToken") val deviceToken: String,
    @SerialName("deviceId") val deviceId: String?,
    @SerialName("platform") val platform: String,
    @SerialName("transport") val transport: String? = null,
    @SerialName("deviceName") val deviceName: String?,
    @SerialName("appVersion") val appVersion: String?,
    // Display only: the server's approval prompt shows it next to deviceName (#516).
    @SerialName("osVersion") val osVersion: String? = null,
    // WebPush encryption keys (RFC 8291), present only for transport="unifiedpush".
    @SerialName("p256dh") val p256dh: String? = null,
    @SerialName("auth") val auth: String? = null,
) {
    /** Redacted: the pairing token authorises registration. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "NativeRegistrationRequest(redacted)"
}

@Serializable
data class NativeRegistrationResponse(
    @SerialName("ok") val ok: Boolean = false,
    @SerialName("synced") val synced: Boolean = false,
    @SerialName("deviceId") val deviceId: String? = null,
    // Minted fresh per registration and returned only here; persist unconditionally.
    @SerialName("deviceSecret") val deviceSecret: String? = null,
    // Current delivery mode for this user ("push" | "pull") and the endpoint to poll
    // when in pull mode. Both may be absent on older servers.
    @SerialName("deliveryMode") val deliveryMode: String? = null,
    @SerialName("pullEndpoint") val pullEndpoint: String? = null,
    // The transport the server actually stored, echoed back. Absent on older servers.
    @SerialName("transport") val transport: String? = null,
    // A 202 (pending approval, docs/device-approval.md in KyPost-Server) adds these.
    @SerialName("status") val status: String? = null,
    @SerialName("error") val error: String? = null,
    @SerialName("approvalCode") val approvalCode: String? = null,
    @SerialName("expiresAt") val expiresAt: String? = null,
    @SerialName("statusEndpoint") val statusEndpoint: String? = null,
    @SerialName("pollIntervalSeconds") val pollIntervalSeconds: Long? = null,
) {
    /** Redacted: carries a freshly minted device secret. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "NativeRegistrationResponse(redacted)"
}

/** The server-provided pull endpoint wins only if it is same-origin with the paired server. */
fun resolvePullEndpoint(serverUrl: String, provided: String?): String =
    resolveSameOrigin(serverUrl, "/api/notifications/native/pull", provided)

/** The pairing-status endpoint from a 202, by the same rule as [resolvePullEndpoint]. */
fun resolvePairingStatusEndpoint(serverUrl: String, provided: String?): String =
    resolveSameOrigin(serverUrl, "/api/notifications/native/pairing-status", provided)

private fun resolveSameOrigin(serverUrl: String, path: String, provided: String?): String {
    val fallback = pairingEndpoint(serverUrl, path)?.toString() ?: return ""
    val candidate = provided?.takeIf { it.isNotBlank() } ?: return fallback
    return if (pairingUrlHost(candidate) != null && sameOrigin(candidate, serverUrl)) {
        candidate
    } else {
        fallback
    }
}

/** The wire boundary keeps `String` — this is the JSON contract, and [PushTransport] is what every
 *  caller above it uses. */
object NativeRegistrationRequestMapper {
    fun map(
        pairing: PairingData,
        token: String,
        transport: String? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationRequest {
        return NativeRegistrationRequest(
            subscriberId = pairing.subscriberId,
            pairingToken = pairing.pairingToken,
            deviceToken = token,
            deviceId = pairing.deviceId,
            platform = "android",
            transport = transport,
            deviceName = Build.MODEL,
            appVersion = "KyPost for Android v$APP_VERSION",
            osVersion = Build.VERSION.RELEASE?.let { "Android $it" },
            p256dh = p256dh,
            auth = auth,
        )
    }
}

sealed class NativeRegistrationResult {
    data class Success(
        val syncedAtEpochMs: Long,
        val deviceId: String?,
        val deviceSecret: String?,
        val deliveryMode: DeliveryMode = DeliveryMode.PUSH,
        val pullEndpoint: String? = null,
        /** The transport the server confirmed, or null when it did not echo the field back (older
         *  servers) or sent something this client does not recognise. */
        val transport: PushTransport? = null,
        // TOFU SPKI pin from this call's handshake, with the host it was seen on. Caller persists it.
        val tlsPin: TlsPin? = null,
    ) : NativeRegistrationResult() {
        /** Redacted: carries a freshly minted device secret. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Success(redacted)"
    }
    /** 202: the server holds this device until the user approves it on the web page that showed
     *  the code (KyPost-Server `docs/device-approval.md`). Memory only: nothing here is persisted
     *  unless the approval arrives, and [wipe] drops the secret on cancel, denial or expiry.
     *  Carries the [pairing] and [credential] it was registered with so completion can persist
     *  exactly what a 200 would have. */
    class Pending(
        val pairing: PairingData,
        val credential: PushRegistrationCredential,
        val deviceId: String,
        deviceSecret: String,
        val approvalCode: String,
        val expiresAtEpochMs: Long,
        val statusEndpoint: String,
        val pollIntervalSeconds: Long,
        val tlsPin: TlsPin?,
    ) : NativeRegistrationResult() {
        /** Valid for the pairing-status endpoint only; null once wiped. */
        @Volatile var deviceSecret: String? = deviceSecret
            private set

        fun wipe() {
            deviceSecret = null
        }

        /** Redacted: carries a device secret. */
        override fun toString(): String = "Pending(redacted)"
    }

    data class Error(
        val message: String,
        val expiredPairingToken: Boolean = false,
        val wipeOwed: Boolean = false,
        /** The pairing-status endpoint answered 410, or the pending request expired. */
        val notApproved: Boolean = false,
    ) : NativeRegistrationResult()
}

/** One answer from `GET native/pairing-status`. */
sealed class PairingStatus {
    /** 202: still waiting; the server may change the interval. */
    data class Waiting(val pollIntervalSeconds: Long?) : PairingStatus()

    /** 200: approved. [deviceId] wins over the pending one: the server may have merged rows. */
    data class Approved(
        val deviceId: String?,
        val deliveryMode: DeliveryMode,
        val pullEndpoint: String?,
        val transport: PushTransport?,
    ) : PairingStatus()

    /** 410: denied, expired or unknown — the server deliberately does not say which. */
    object Rejected : PairingStatus()

    /** Network failure, 429, 5xx or anything unexpected: back off and ask again. */
    data class Retry(val retryAfterSeconds: Long?) : PairingStatus()
}

class NativeRegistrationClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun register(
        pairing: PairingData,
        token: String,
        nowEpochMs: Long = System.currentTimeMillis(),
        transport: PushTransport? = null,
        p256dh: String? = null,
        auth: String? = null,
    ): NativeRegistrationResult {
        if (token.isBlank()) return NativeRegistrationResult.Error("FCM token is empty")
        if (pairingUrlHost(pairing.serverUrl) == null ||
            pairingUrlHost(pairing.registrationUrl) == null ||
            !sameOrigin(pairing.registrationUrl, pairing.serverUrl)
        ) {
            return NativeRegistrationResult.Error("Registration URL is not valid")
        }

        val request = NativeRegistrationRequestMapper.map(
            pairing = pairing,
            token = token,
            transport = transport?.wire,
            p256dh = p256dh,
            auth = auth,
        )
        val httpRequest = Request.Builder()
            .url(pairing.registrationUrl)
            .post(json.encodeToString(request).toRequestBody(JSON_MEDIA_TYPE))
            // Both halves or neither: a device id sent alone reads as an uncredentialed rebind attempt.
            .apply {
                val deviceId = pairing.deviceId
                val deviceSecret = pairing.deviceSecret
                if (!deviceId.isNullOrBlank() && !deviceSecret.isNullOrBlank()) {
                    pairingAuthHeaders(deviceId, deviceSecret)
                }
            }
            // Pins THIS request when the pairing link published a leaf SPKI. Without it the
            // pairing token, endpoint and WebPush keys go out inside the TOFU window, and the
            // certificate is only trusted after they have already been disclosed.
            .apply {
                val linkPin = pairing.spkiPin
                val host = pairing.registrationUrl.toHttpUrlOrNull()?.host
                if (linkPin != null && host != null) {
                    tag(org.kysecurity.mail.LinkPin::class.java, org.kysecurity.mail.LinkPin(host, linkPin))
                }
            }
            .build()
        // The host this call's handshake will be with — the pin below is only meaningful together
        // with it, since it is this URL, not pairing.serverUrl, that the certificate belongs to.
        val registrationHost = pairing.registrationUrl.toHttpUrlOrNull()?.host

        val result = withContext(Dispatchers.IO) {
            // Captures the handshake alongside code/body (not just the mapped DTO) so a
            // successful call can seed the TOFU TLS pin — see the `tlsPin` computation below.
            callFactory.executeSync(httpRequest) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.handshake)
            }
        }
        val (code, rawBody, handshake) = result.getOrNull()
            ?: return NativeRegistrationResult.Error(result.exceptionOrNull()?.message ?: "Failed to register device")

        return when (code) {
            202 -> pending(pairing, token, transport, p256dh, auth, rawBody, nowEpochMs, registrationHost, handshake)
            200 -> {
                val body = runCatching { json.decodeFromString<NativeRegistrationResponse>(rawBody) }.getOrNull()
                if (body?.ok == true && body.synced && body.deviceSecret.isNullOrBlank()) {
                    // A successful registration always mints a secret; a 200 without one is not success.
                    NativeRegistrationResult.Error("Registration did not return a device secret")
                } else if (body?.ok == true && body.synced) {
                    NativeRegistrationResult.Success(
                        syncedAtEpochMs = nowEpochMs,
                        deviceId = body.deviceId,
                        deviceSecret = body.deviceSecret,
                        deliveryMode = DeliveryMode.fromWire(body.deliveryMode),
                        pullEndpoint = body.pullEndpoint,
                        transport = PushTransport.fromWire(body.transport),
                        // THE LEAF, and only the leaf — see [SpkiPinner.pinsForChain]. Pinning an
                        // issuer admits every certificate that issuer signs, which for a public CA
                        // is every certificate anyone can buy. Installs pinned under the old
                        // whole-chain rule keep validating and narrow on the next successful
                        // resync; renewal with a new key is a re-trust, not a widening.
                        tlsPin = registrationHost?.let { host ->
                            SpkiPinner.pinsForChain(handshake?.peerCertificates.orEmpty())
                                .takeIf { it.isNotEmpty() }
                                ?.let { TlsPin(host, it) }
                        },
                    )
                } else {
                    NativeRegistrationResult.Error("Registration did not confirm sync")
                }
            }
            400 -> NativeRegistrationResult.Error("Malformed request or missing fields")
            401 -> NativeRegistrationResult.Error(
                message = "Pairing token expired or invalid",
                expiredPairingToken = true,
            )
            503 -> NativeRegistrationResult.Error("Pairing not configured on backend")
            // The device row exists and belongs to a credential this call did not present. Not a
            // transport failure and not a retry: re-pairing is the only thing that resolves it.
            409 -> conflict(rawBody)
            else -> NativeRegistrationResult.Error("Failed to register device ($code)")
        }
    }

    private fun conflict(rawBody: String): NativeRegistrationResult.Error {
        val serverError = runCatching { json.decodeFromString<NativeRegistrationResponse>(rawBody) }
            .getOrNull()?.error.orEmpty()
        return NativeRegistrationResult.Error(
            when {
                // Someone else redeemed this link first. Not transient: say it plainly.
                serverError.contains("already used", ignoreCase = true) ->
                    "This code was already used. If you did not use it, deny the request on the web page."
                serverError.contains("already waiting for approval", ignoreCase = true) ->
                    "This device is already waiting for approval. Approve it on the web page, or wait 5 minutes and scan a new code."
                serverError.contains("too many devices are waiting", ignoreCase = true) ->
                    "Too many devices are waiting for approval. Approve or deny them on the web page first."
                else -> "This device is already registered with a different credential — re-pair it"
            },
        )
    }

    private fun pending(
        pairing: PairingData,
        token: String,
        transport: PushTransport?,
        p256dh: String?,
        auth: String?,
        rawBody: String,
        nowEpochMs: Long,
        registrationHost: String?,
        handshake: okhttp3.Handshake?,
    ): NativeRegistrationResult {
        val body = runCatching { json.decodeFromString<NativeRegistrationResponse>(rawBody) }.getOrNull()
        val deviceId = body?.deviceId?.takeIf { it.isNotBlank() }
        val deviceSecret = body?.deviceSecret?.takeIf { it.isNotBlank() }
        val code = body?.approvalCode?.takeIf { APPROVAL_CODE.matches(it) }
        if (body?.status != "pending" || deviceId == null || deviceSecret == null || code == null) {
            return NativeRegistrationResult.Error("Registration did not return an approval request")
        }
        val expiresAt = body.expiresAt
            ?.let { runCatching { java.time.Instant.parse(it).toEpochMilli() }.getOrNull() }
            // The server's fixed pending lifetime, if it sent no readable expiry.
            ?: (nowEpochMs + PENDING_LIFETIME_MS)
        return NativeRegistrationResult.Pending(
            pairing = pairing,
            credential = PushRegistrationCredential(token, transport, p256dh, auth),
            deviceId = deviceId,
            deviceSecret = deviceSecret,
            approvalCode = code,
            expiresAtEpochMs = expiresAt,
            statusEndpoint = resolvePairingStatusEndpoint(pairing.serverUrl, body.statusEndpoint),
            pollIntervalSeconds = body.pollIntervalSeconds ?: DEFAULT_POLL_SECONDS,
            // The same TOFU leaf a 200 captures; persisted only once the device is approved.
            tlsPin = registrationHost?.let { host ->
                SpkiPinner.pinsForChain(handshake?.peerCertificates.orEmpty())
                    .takeIf { it.isNotEmpty() }
                    ?.let { TlsPin(host, it) }
            },
        )
    }

    /** `GET native/pairing-status` with the pending credentials. Pinned to the leaf the 202 was
     *  served with while nothing is stored yet; once a pin is stored, the factory uses that. */
    suspend fun pairingStatus(pending: NativeRegistrationResult.Pending): PairingStatus {
        val secret = pending.deviceSecret ?: return PairingStatus.Rejected
        val url = pending.statusEndpoint.takeIf { pairingUrlHost(it) != null }
            ?: return PairingStatus.Rejected
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(pending.deviceId, secret)
            .apply {
                val pin = pending.tlsPin
                if (pin != null && pin.host.equals(url.toHttpUrlOrNull()?.host, ignoreCase = true)) {
                    // ponytail: LinkPin holds one hash; the 202 pin is leaf-only, so first() is it.
                    tag(org.kysecurity.mail.LinkPin::class.java, org.kysecurity.mail.LinkPin(pin.host, pin.spkiSha256.first()))
                }
            }
            .build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.header("Retry-After"))
            }
        }
        val (code, rawBody, retryAfter) = result.getOrNull() ?: return PairingStatus.Retry(null)
        val body = runCatching { json.decodeFromString<NativeRegistrationResponse>(rawBody) }.getOrNull()
        return when (code) {
            200 -> if (body?.ok == true && body.status == "approved") {
                PairingStatus.Approved(
                    deviceId = body.deviceId?.takeIf { it.isNotBlank() },
                    deliveryMode = DeliveryMode.fromWire(body.deliveryMode),
                    pullEndpoint = body.pullEndpoint,
                    transport = PushTransport.fromWire(body.transport),
                )
            } else {
                PairingStatus.Retry(null)
            }
            202 -> PairingStatus.Waiting(body?.pollIntervalSeconds)
            410 -> PairingStatus.Rejected
            else -> PairingStatus.Retry(PullNotificationClient.parseRetryAfterSeconds(retryAfter))
        }
    }

    private companion object {
        val APPROVAL_CODE = Regex("^[0-9]{6}$")
        const val DEFAULT_POLL_SECONDS = 3L
        const val PENDING_LIFETIME_MS = 5 * 60_000L
    }
}
