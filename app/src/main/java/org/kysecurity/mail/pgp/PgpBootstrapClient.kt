package org.kysecurity.mail.pgp

import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pairingAuthHeaders
import org.kysecurity.mail.push.pairingEndpoint
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.Request

sealed class PgpBootstrapResult {
    /** [protection] is `"server"`, `"client"`, or `""` for an account with no identity. */
    data class Success(
        val hasIdentity: Boolean,
        val protection: String,
        val publicKey: String,
        /** Delivery `From` must equal this exactly or the relay answers 403. */
        val accountAddress: String = "",
        /** The primary address, then every verified send-as alias. */
        val addresses: List<String> = emptyList(),
    ) : PgpBootstrapResult()

    data class Failed(val message: String) : PgpBootstrapResult()
}

/** The response's `fingerprint` is deliberately unused — [PgpFingerprint] hashes the key bytes. */
@Serializable
private data class PgpBootstrapDto(
    val hasIdentity: Boolean = false,
    val protection: String = "",
    val publicKey: String = "",
    /** Primary address first, then every verified send-as alias. */
    val suggestedUserIDs: List<String> = emptyList(),
)

class PgpBootstrapClient(
    private val json: Json = Json { ignoreUnknownKeys = true },
    // Injected Call.Factory; see PairingAuthHeaders.kt for why every credentialed client takes one.
    private val callFactory: Call.Factory,
) {
    suspend fun fetch(serverUrl: String, deviceId: String, deviceSecret: String): PgpBootstrapResult {
        val url = pairingEndpoint(serverUrl, "/api/pgp/bootstrap")
            ?: return PgpBootstrapResult.Failed("Server URL is not valid")
        val request = Request.Builder().url(url).get()
            .pairingAuthHeaders(deviceId, deviceSecret)
            .build()

        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
        }
        val (code, rawBody) = result.getOrNull()
            ?: return PgpBootstrapResult.Failed(result.exceptionOrNull()?.message ?: "Network error")

        // Only 200 is JSON here; every other status returns plain text, so no decoder runs over it.
        if (code != 200) return PgpBootstrapResult.Failed("PGP bootstrap failed ($code)")
        val parsed = runCatching { json.decodeFromString<PgpBootstrapDto>(rawBody) }.getOrNull()
            ?: return PgpBootstrapResult.Failed("Malformed PGP bootstrap response")
        return PgpBootstrapResult.Success(
            hasIdentity = parsed.hasIdentity,
            protection = parsed.protection,
            publicKey = parsed.publicKey,
            accountAddress = parsed.suggestedUserIDs.firstOrNull().orEmpty(),
            addresses = parsed.suggestedUserIDs,
        )
    }
}
