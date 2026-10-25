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
) {
    /** Redacted: carries a freshly minted device secret. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "NativeRegistrationResponse(redacted)"
}

/** The server-provided pull endpoint wins only if it is same-origin with the paired server. */
fun resolvePullEndpoint(serverUrl: String, provided: String?): String {
    val fallback = pairingEndpoint(serverUrl, "/api/notifications/native/pull")?.toString() ?: return ""
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
    data class Error(val message: String, val expiredPairingToken: Boolean = false, val wipeOwed: Boolean = false) : NativeRegistrationResult()
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
            409 -> NativeRegistrationResult.Error(
                "This device is already registered with a different credential — re-pair it",
            )
            else -> NativeRegistrationResult.Error("Failed to register device ($code)")
        }
    }
}
