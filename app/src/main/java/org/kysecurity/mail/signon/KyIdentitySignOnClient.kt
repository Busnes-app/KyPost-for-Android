package org.kysecurity.mail.signon

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
import okhttp3.Response
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.push.NativePairingDeepLinkParser
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.push.pairingEndpoint
import org.kysecurity.mail.push.pairingUrlHost

data class SignOnConfig(val issuerUrl: String, val clientId: String)

sealed class SignOnConfigResult {
    data class Ready(val config: SignOnConfig) : SignOnConfigResult()
    data class Unavailable(val reason: String) : SignOnConfigResult()
}

@Serializable
private data class SsoConfigResponse(
    @SerialName("enabled") val enabled: Boolean = false,
    @SerialName("issuerUrl") val issuerUrl: String = "",
    @SerialName("clientId") val clientId: String = "",
) {
    override fun toString(): String = "SsoConfigResponse(redacted)"
}

@Serializable
internal data class SignOnRequest(@SerialName("idToken") val idToken: String) {
    override fun toString(): String = "SignOnRequest(redacted)"
}

@Serializable
private data class SignOnResponse(
    @SerialName("configured") val configured: Boolean = false,
    @SerialName("configurationError") val configurationError: String = "",
    @SerialName("deepLink") val deepLink: String = "",
) {
    override fun toString(): String = "SignOnResponse(redacted)"
}

/** Reads the relay's SSO config and swaps a KyIdentity ID token for a pairing deep link. */
class KyIdentitySignOnClient(
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    suspend fun config(serverUrl: String): SignOnConfigResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/auth/sso-config")
            ?: return SignOnConfigResult.Unavailable("Server URL must use https")
        val request = Request.Builder().url(endpoint).get().build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request, ::readBounded)
        }
        val (code, raw) = result.getOrNull()
            ?: return SignOnConfigResult.Unavailable(result.exceptionOrNull()?.message ?: "Could not reach the server")
        if (code == 404) return SignOnConfigResult.Unavailable("This server does not use KyIdentity sign-in")
        if (code != 200) return SignOnConfigResult.Unavailable("Could not read the server's sign-in settings ($code)")
        val body = runCatching { json.decodeFromString<SsoConfigResponse>(raw) }.getOrNull()
            ?: return SignOnConfigResult.Unavailable("The server returned an unreadable sign-in configuration")
        if (!body.enabled || body.issuerUrl.isBlank() || body.clientId.isBlank()) {
            return SignOnConfigResult.Unavailable("This server does not use KyIdentity sign-in")
        }
        return SignOnConfigResult.Ready(SignOnConfig(body.issuerUrl.trimEnd('/'), body.clientId))
    }

    suspend fun signOn(serverUrl: String, idToken: String): PairingParseResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/auth/native/signon")
            ?: return PairingParseResult.Error("Server URL must use https")
        val request = Request.Builder()
            .url(endpoint)
            .post(json.encodeToString(SignOnRequest(idToken)).toRequestBody("application/json".toMediaType()))
            .build()
        val result = withContext(Dispatchers.IO) {
            callFactory.executeSync(request, ::readBounded)
        }
        val (code, raw) = result.getOrNull()
            ?: return PairingParseResult.Error(result.exceptionOrNull()?.message ?: "Could not reach the server")
        if (code != 200) {
            val host = endpoint.host
            val message = when (code) {
                403 -> refusalText(raw)
                429 -> "Too many attempts. Try again later"
                503 -> "$host is not set up for KyIdentity sign-in or pairing"
                else -> "Could not sign in to $host ($code)"
            }
            return PairingParseResult.Error(message)
        }
        val body = runCatching { json.decodeFromString<SignOnResponse>(raw) }.getOrNull()
            ?: return PairingParseResult.Error("The server returned an unreadable pairing response")
        if (!body.configured || body.deepLink.isBlank()) {
            return PairingParseResult.Error(body.configurationError.ifBlank { "Pairing is not configured on the server" })
        }
        val parsed = NativePairingDeepLinkParser.parse(body.deepLink)
        if (parsed is PairingParseResult.Success && pairingUrlHost(parsed.pairing.serverUrl) != endpoint.host) {
            return PairingParseResult.Error("The server returned a pairing link for a different host")
        }
        return parsed
    }
}

private const val MAX_ERROR_BYTES = 4L * 1024
private const val MAX_REFUSAL_CHARS = 200
private const val REFUSED = "KyIdentity sign-in was refused"

/** Failure bodies reach a Toast, so they are read bounded. */
private fun readBounded(response: Response): Pair<Int, String> {
    val body = if (response.code == 200) response.body?.string() else response.peekBody(MAX_ERROR_BYTES).string()
    return response.code to body.orEmpty()
}

/** The relay's 403 wording when it is plain text; anything else (a proxy's HTML page) is not ours. */
private fun refusalText(raw: String): String {
    if ('<' in raw) return REFUSED
    return raw.trim().lineSequence().first().take(MAX_REFUSAL_CHARS).ifBlank { REFUSED }
}
