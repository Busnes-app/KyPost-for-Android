package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody

private val JSON_MEDIA_TYPE = "application/json".toMediaType()

/** Versions this build can open. 3 is advertised only because #112/#115/#116 passed the native
 *  complete-ring persistence checks, which is the server's condition for the claim. */
private val SUPPORTED_ENVELOPE_VERSIONS = listOf(ENVELOPE_VERSION_LEGACY, ENVELOPE_VERSION_KEYRING)

@Serializable
private data class PublishEnrollmentKeyRequest(
    @SerialName("publicKey") val publicKey: String,
    @SerialName("envelopeVersions") val envelopeVersions: List<Int>,
)

/** The three metadata fields go together: absent for the legacy boolean, all present for a
 *  keyring acknowledgement. The server answers 400 to any other combination. */
@Serializable
private data class EnrollmentStateRequest(
    @SerialName("encryptionEnrolled") val encryptionEnrolled: Boolean,
    @SerialName("envelopeVersion") val envelopeVersion: Int? = null,
    @SerialName("materialGeneration") val materialGeneration: Long? = null,
    @SerialName("fingerprint") val fingerprint: String? = null,
)

@Serializable
private data class KeyringStateDto(
    @SerialName("primaryFingerprints") val primaryFingerprints: List<String> = emptyList(),
    @SerialName("keyFingerprints") val keyFingerprints: List<String> = emptyList(),
)

@Serializable
private data class DeviceEnvelopeResponse(
    @SerialName("envelope") val envelope: String? = null,
    /** Absent from servers before KyPost-Server #210; a v3 envelope without it is refused. */
    @SerialName("version") val version: Int? = null,
    @SerialName("fingerprint") val fingerprint: String? = null,
    @SerialName("materialGeneration") val materialGeneration: Long? = null,
    @SerialName("keyring") val keyring: KeyringStateDto? = null,
)

/** What the server recorded when it delivered the envelope; the ring that opens must match it. */
internal data class DeliveryMetadata(
    val version: Int,
    val fingerprint: String,
    /** Null on a legacy account, where the server omits the field. */
    val materialGeneration: Long?,
    val primaryFingerprints: List<String>?,
    val keyFingerprints: List<String>?,
)

/** What this device tells the server it holds. */
internal sealed class EnrollmentReport {
    /** Clears the marker and the server's delivery record: a fresh delivery is needed afterwards. */
    object NotEnrolled : EnrollmentReport()

    /** The bare boolean, meaning "opens a v2 envelope". A converted account refuses it. */
    object Legacy : EnrollmentReport()

    /** Confirms the v3 delivery the server recorded for this device, and nothing else. */
    data class Keyring(val materialGeneration: Long, val fingerprint: String) : EnrollmentReport()
}

internal sealed class EnrollmentCallResult {
    object Ok : EnrollmentCallResult()
    /** [delivery] is null only from a server too old to record deliveries. */
    data class Envelope(val envelope: String, val delivery: DeliveryMetadata? = null) : EnrollmentCallResult()

    /** 409: the server compared the claim with its own record and refused. Never retried. */
    object Conflict : EnrollmentCallResult()
    /** 404 covers both "never sealed" and "expired" — indistinguishable by design, and both mean
     *  re-run the ceremony. One result so a caller cannot accidentally split them. */
    object NotFound : EnrollmentCallResult()
    object Unauthorized : EnrollmentCallResult()
    data class RateLimited(val retryAfterSeconds: Long?) : EnrollmentCallResult()
    data class Failed(val message: String) : EnrollmentCallResult()
}

/** The three device-authenticated enrollment calls. Endpoints come from the paired origin only. */
internal class EnrollmentClients(
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {

    suspend fun publishKey(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        encodedPublicKey: String,
    ): EnrollmentCallResult {
        val body = json.encodeToString(PublishEnrollmentKeyRequest(encodedPublicKey, SUPPORTED_ENVELOPE_VERSIONS))
        return call(serverUrl, "/api/pgp/device/enrollment-key", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    suspend fun fetchEnvelope(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
    ): EnrollmentCallResult =
        // No slot parameter: the server builds it from the verified credential, and a test there
        // asserts a ?slot= query is ignored so the route cannot quietly grow one.
        call(serverUrl, "/api/pgp/device/envelope", deviceId, deviceSecret, body = null) { raw ->
            val parsed = runCatching { json.decodeFromString<DeviceEnvelopeResponse>(raw) }.getOrNull()
            val envelope = parsed?.envelope
            when {
                parsed == null || envelope.isNullOrBlank() -> EnrollmentCallResult.Failed("Malformed envelope response")
                parsed.version == null || parsed.fingerprint == null -> EnrollmentCallResult.Envelope(envelope)
                else -> EnrollmentCallResult.Envelope(
                    envelope,
                    DeliveryMetadata(
                        version = parsed.version,
                        fingerprint = parsed.fingerprint,
                        materialGeneration = parsed.materialGeneration,
                        primaryFingerprints = parsed.keyring?.primaryFingerprints,
                        keyFingerprints = parsed.keyring?.keyFingerprints,
                    ),
                )
            }
        }

    suspend fun reportState(
        serverUrl: String,
        deviceId: String,
        deviceSecret: String,
        report: EnrollmentReport,
    ): EnrollmentCallResult {
        // Always written explicitly. This route requires the field — unlike the tri-state pointer
        // on registration, an absent value here is a 400, not "no opinion".
        val request = when (report) {
            EnrollmentReport.NotEnrolled -> EnrollmentStateRequest(false)
            EnrollmentReport.Legacy -> EnrollmentStateRequest(true)
            is EnrollmentReport.Keyring -> EnrollmentStateRequest(
                true, ENVELOPE_VERSION_KEYRING, report.materialGeneration, report.fingerprint,
            )
        }
        val body = json.encodeToString(request)
        return call(serverUrl, "/api/pgp/device/enrollment-state", deviceId, deviceSecret, body) {
            EnrollmentCallResult.Ok
        }
    }

    private suspend fun call(
        serverUrl: String,
        path: String,
        deviceId: String,
        deviceSecret: String,
        body: String?,
        onSuccess: (String) -> EnrollmentCallResult,
    ): EnrollmentCallResult {
        val url = pairingEndpoint(serverUrl, path)
            ?: return EnrollmentCallResult.Failed("Server URL is not valid")
        val request = Request.Builder()
            .url(url)
            .apply { if (body == null) get() else post(body.toRequestBody(JSON_MEDIA_TYPE)) }
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response ->
                Triple(response.code, response.body?.string().orEmpty(), response.header("Retry-After"))
            }
        }
        val (code, raw, retryAfter) = result.getOrNull()
            ?: return EnrollmentCallResult.Failed(result.exceptionOrNull()?.message ?: "Request failed")

        return when (code) {
            200 -> onSuccess(raw)
            401 -> EnrollmentCallResult.Unauthorized
            404 -> EnrollmentCallResult.NotFound
            409 -> EnrollmentCallResult.Conflict
            429 -> EnrollmentCallResult.RateLimited(retryAfter?.toLongOrNull())
            else -> EnrollmentCallResult.Failed("Request failed ($code)")
        }
    }
}
