package org.kysecurity.mail.push

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
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pgp.hkdfSha256
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Serializable
private data class PasswordPairingRequest(
    @SerialName("username") val username: String,
    @SerialName("authSecret") val authSecret: String,
) {
    override fun toString(): String = "PasswordPairingRequest(redacted)"
}

@Serializable
private data class LoginParams(@SerialName("salt") val salt: String = "", @SerialName("iterations") val iterations: Int = 0)

@Serializable
private data class PasswordPairingResponse(@SerialName("deepLink") val deepLink: String = "")

// Bounds of the server's users.MinLoginIterations / MaxLoginIterations, as in the web client.
private const val MIN_ITERATIONS = 100_000
private const val MAX_ITERATIONS = 12_000_000

/**
 * The web client's frontend/src/lib/authSecret.ts, so the password never leaves the device:
 * hex(HKDF-SHA256(PBKDF2-SHA256(password, base64(salt), iterations, 32), salt "", "kypost/auth/v1", 32)).
 * HKDF's empty salt is passed as 32 zero bytes, which RFC 5869 defines as the same key.
 */
internal fun deriveAuthSecret(password: String, salt: String, iterations: Int): String {
    require(iterations in MIN_ITERATIONS..MAX_ITERATIONS) { "unsupported work factor" }
    val spec = PBEKeySpec(password.toCharArray(), Base64.getDecoder().decode(salt), iterations, 256)
    val stretch = try {
        SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).encoded
    } finally {
        spec.clearPassword()
    }
    val secret = hkdfSha256(stretch, ByteArray(32), "kypost/auth/v1".toByteArray(), 32)
    stretch.fill(0)
    return secret.joinToString("") { "%02x".format(it) }
}

class PasswordPairingClient(
    private val callFactory: Call.Factory,
    private val json: Json = Json { ignoreUnknownKeys = true },
) {
    suspend fun mint(serverUrl: String, username: String, password: String): PairingParseResult {
        val endpoint = pairingEndpoint(serverUrl, "/api/notifications/review-pairing")
        val paramsEndpoint = pairingEndpoint(serverUrl, "/api/auth/login-params")
        if (endpoint == null || paramsEndpoint == null) return PairingParseResult.Error("Server URL must use https")
        if (username.isBlank() || password.isBlank()) return PairingParseResult.Error("Enter your username and password")
        val user = username.trim()
        val paramsUrl = paramsEndpoint.newBuilder().addQueryParameter("username", user).build()

        val (paramsCode, paramsRaw) = call(Request.Builder().url(paramsUrl).get().build())
            .getOrElse { return unreachable(it) }
        if (paramsCode != 200) return PairingParseResult.Error(errorFor(paramsCode))
        val authSecret = withContext(Dispatchers.Default) {
            runCatching {
                val params = json.decodeFromString<LoginParams>(paramsRaw)
                deriveAuthSecret(password, params.salt, params.iterations)
            }.getOrNull()
        } ?: return PairingParseResult.Error("The server sent unusable sign-in parameters")

        val body = json.encodeToString(PasswordPairingRequest(user, authSecret))
        val (code, raw) = call(Request.Builder().url(endpoint).post(body.toRequestBody("application/json".toMediaType())).build())
            .getOrElse { return unreachable(it) }
        if (code != 200) return PairingParseResult.Error(errorFor(code))
        val deepLink = runCatching { json.decodeFromString<PasswordPairingResponse>(raw).deepLink }.getOrNull().orEmpty()
        return NativePairingDeepLinkParser.parse(deepLink)
    }

    private suspend fun call(request: Request): Result<Pair<Int, String>> = withContext(Dispatchers.IO) {
        callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
    }

    private fun unreachable(e: Throwable) = PairingParseResult.Error(e.message ?: "Could not reach the server")

    private fun errorFor(code: Int) = when (code) {
        401 -> "Username or password is incorrect"
        403 -> "This account requires an interactive sign-in"
        404 -> "Fast pairing is not enabled on this server"
        429 -> "Too many attempts. Try again later"
        else -> "Could not pair with the server ($code)"
    }
}
