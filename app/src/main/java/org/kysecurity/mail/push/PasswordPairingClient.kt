package org.kysecurity.mail.push

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.Call
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.kysecurity.mail.executeSync
import org.kysecurity.mail.pgp.hkdfSha256
import java.security.MessageDigest
import java.util.Base64
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.PBEKeySpec

@Serializable
private data class PasswordPairingRequest(
    @SerialName("username") val username: String,
    @SerialName("authSecret") val authSecret: String,
    @SerialName("captchaToken") val captchaToken: String? = null,
) {
    override fun toString(): String = "PasswordPairingRequest(redacted)"
}

@Serializable
private data class LoginParams(@SerialName("salt") val salt: String = "", @SerialName("iterations") val iterations: Int = 0)

/** `provider` is "" when CAPTCHA is off, "pow" for the built-in check, else a third party. */
@Serializable
private data class CaptchaConfig(@SerialName("provider") val provider: String)

/** KyPost-Server captcha.Challenge. Every field is HMAC-signed and echoed back unchanged. */
@Serializable
internal data class PowChallenge(
    val algorithm: String,
    val salt: String,
    val challenge: String,
    val maxnumber: Int,
    val expires: Long,
    val clientip: String,
    val signature: String,
)

// Field order matches the web client's token byte for byte; the server does not depend on it.
@Serializable
private data class PowSolution(
    val algorithm: String,
    val salt: String,
    val challenge: String,
    val maxnumber: Int,
    val expires: Long,
    val clientip: String,
    val signature: String,
    val number: Int,
)

// 10x the server's escalation ceiling (1,000,000): room for a raised POW_MAX_NUMBER, not a hang.
private const val MAX_POW_NUMBER = 10_000_000

// The server's exact format (captcha.IssueAt): salt is hex of 16 bytes, challenge a SHA-256 in hex.
private val POW_SALT = Regex("[0-9a-f]{32}")
private val POW_CHALLENGE = Regex("[0-9a-f]{64}")

/**
 * frontend/src/lib/pow.ts: find number in 0..maxnumber with SHA-256(salt + number) == challenge,
 * then return base64(JSON(challenge + number)). Null when malformed or no answer is in range.
 * Cancellable: leaving the screen stops the search.
 */
internal suspend fun solvePow(c: PowChallenge, json: Json): String? {
    if (c.algorithm != "SHA-256" || c.maxnumber !in 0..MAX_POW_NUMBER ||
        !POW_SALT.matches(c.salt) || !POW_CHALLENGE.matches(c.challenge)
    ) return null
    val target = ByteArray(32) { c.challenge.substring(it * 2, it * 2 + 2).toInt(16).toByte() }
    val salted = MessageDigest.getInstance("SHA-256").apply { update(c.salt.toByteArray()) }
    var number = -1
    for (n in 0..c.maxnumber) {
        if (n % 4096 == 0) currentCoroutineContext().ensureActive()
        val sha = salted.clone() as MessageDigest
        if (MessageDigest.isEqual(sha.digest(n.toString().toByteArray()), target)) {
            number = n
            break
        }
    }
    if (number < 0) return null
    val solution = PowSolution(c.algorithm, c.salt, c.challenge, c.maxnumber, c.expires, c.clientip, c.signature, number)
    return Base64.getEncoder().encodeToString(json.encodeToString(solution).toByteArray())
}

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
        pairingEndpoint(serverUrl, "") ?: return PairingParseResult.Error("Server URL must use https")
        fun api(path: String) = checkNotNull(pairingEndpoint(serverUrl, path))
        if (username.isBlank() || password.isBlank()) return PairingParseResult.Error("Enter your username and password")
        val user = username.trim()

        // Checked first so an unsolvable CAPTCHA fails before the slow derivation.
        val (cfgCode, cfgRaw) = get(api("/api/auth/captcha-config")).getOrElse { return unreachable(it) }
        val provider = runCatching { json.decodeFromString<CaptchaConfig>(cfgRaw).provider }.getOrNull()
        if (cfgCode != 200 || provider == null) return PairingParseResult.Error("Could not read the server's security-check settings ($cfgCode)")
        if (provider != "" && provider != "pow") {
            return PairingParseResult.Error("This server uses a third-party CAPTCHA. Review pairing needs CAPTCHA_PROVIDER=pow or CAPTCHA turned off.")
        }

        val paramsUrl = api("/api/auth/login-params").newBuilder().addQueryParameter("username", user).build()
        val (paramsCode, paramsRaw) = get(paramsUrl).getOrElse { return unreachable(it) }
        if (paramsCode != 200) return PairingParseResult.Error(errorFor(paramsCode, paramsRaw))
        val authSecret = withContext(Dispatchers.Default) {
            runCatching {
                val params = json.decodeFromString<LoginParams>(paramsRaw)
                deriveAuthSecret(password, params.salt, params.iterations)
            }.getOrNull()
        } ?: return PairingParseResult.Error("The server sent unusable sign-in parameters")

        // Fetched after the derivation: the challenge expires, and is single-use and IP-bound.
        var captchaToken: String? = null
        if (provider == "pow") {
            val (powCode, powRaw) = get(api("/api/auth/pow-challenge")).getOrElse { return unreachable(it) }
            if (powCode != 200) return PairingParseResult.Error(errorFor(powCode, powRaw))
            val challenge = runCatching { json.decodeFromString<PowChallenge>(powRaw) }.getOrNull()
            // Not inside runCatching, which would swallow the solver's cancellation.
            captchaToken = challenge?.let { withContext(Dispatchers.Default) { solvePow(it, json) } }
                ?: return PairingParseResult.Error("The server sent an unusable security check")
        }

        val body = json.encodeToString(PasswordPairingRequest(user, authSecret, captchaToken))
        val request = Request.Builder().url(api("/api/notifications/review-pairing"))
            .post(body.toRequestBody("application/json".toMediaType())).build()
        val (code, raw) = call(request).getOrElse { return unreachable(it) }
        if (code != 200) return PairingParseResult.Error(errorFor(code, raw))
        val deepLink = runCatching { json.decodeFromString<PasswordPairingResponse>(raw).deepLink }.getOrNull().orEmpty()
        return NativePairingDeepLinkParser.parse(deepLink)
    }

    private suspend fun get(url: HttpUrl) = call(Request.Builder().url(url).get().build())

    private suspend fun call(request: Request): Result<Pair<Int, String>> = withContext(Dispatchers.IO) {
        callFactory.executeSync(request) { response -> response.code to response.body?.string().orEmpty() }
    }

    private fun unreachable(e: Throwable) = PairingParseResult.Error(e.message ?: "Could not reach the server")

    private fun errorFor(code: Int, body: String) = when (code) {
        // verifyLogin's CAPTCHA refusals (failed, expired, address changed) are 401s too.
        401 -> if ("captcha" in body || "security check" in body) "The security check failed. Try again" else "Username or password is incorrect"
        403 -> "This account requires an interactive sign-in"
        404 -> "Fast pairing is not enabled on this server"
        429 -> "Too many attempts. Try again later"
        else -> "Could not pair with the server ($code)"
    }
}
