package org.kysecurity.mail.push

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response
import java.security.MessageDigest
import java.util.Base64
import kotlin.test.assertFailsWith

class PasswordPairingClientTest {
    private val server = "https://mail.example.com"
    private val password = "correct-horse-battery-staple"
    private val zeroSalt = "AAAAAAAAAAAAAAAAAAAAAA=="
    private val link = "kypost://native-pair?sub=s1&srv=https%3A%2F%2Fmail.example.com&reg=https%3A%2F%2Fmail.example.com%2Fapi%2Fnotifications%2Fnative%2Fregister&pt=tok"

    // KyPost-Server users.TestDeriveAuthSecretMatchesTheBrowser; also reproduced with WebCrypto.
    private val sharedVector = "da9fc5d333fdab121f3c302b6191b68657bf806030a32c0cbd47b39b720dc860"

    // Signed by KyPost-Server's captcha.PoWVerifier (answer 3141). powToken is what
    // frontend/src/lib/pow.ts returns for it, and PoWVerifier.Verify accepts it.
    private val powChallenge = """{"algorithm":"SHA-256","salt":"00112233445566778899aabbccddeeff","challenge":"7c1d1743fff40686ae9f7b1a8b253b38f81feb7386550a9789f0bb72ff84093f","maxnumber":5000,"expires":1700000300,"clientip":"203.0.113.9","signature":"5461da4f01099da5d023cec53407d58cfa3980029c3ae8f6a1a5cc5281fd4d2a"}"""
    private val powToken = "eyJhbGdvcml0aG0iOiJTSEEtMjU2Iiwic2FsdCI6IjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmIiwiY2hhbGxlbmdlIjoiN2MxZDE3NDNmZmY0MDY4NmFlOWY3YjFhOGIyNTNiMzhmODFmZWI3Mzg2NTUwYTk3ODlmMGJiNzJmZjg0MDkzZiIsIm1heG51bWJlciI6NTAwMCwiZXhwaXJlcyI6MTcwMDAwMDMwMCwiY2xpZW50aXAiOiIyMDMuMC4xMTMuOSIsInNpZ25hdHVyZSI6IjU0NjFkYTRmMDEwOTlkYTVkMDIzY2VjNTM0MDdkNThjZmEzOTgwMDI5YzNhZThmNmExYTVjYzUyODFmZDRkMmEiLCJudW1iZXIiOjMxNDF9"

    private fun relay(captchaProvider: String, params: String = """{"salt":"$zeroSalt","iterations":100000}""") =
        BodyRecordingCallFactory { req ->
            when (req.url.encodedPath) {
                "/api/auth/captcha-config" -> response(req, """{"provider":"$captchaProvider","siteKey":""}""", 200)
                "/api/auth/login-params" -> response(req, params, 200)
                "/api/auth/pow-challenge" -> response(req, powChallenge, 200)
                else -> response(req, """{"deepLink":"$link"}""", 200)
            }
        }

    @Test
    fun deriveAuthSecret_matchesServerAndBrowser() {
        assertEquals(sharedVector, deriveAuthSecret(password, zeroSalt, 100_000))
        // Pins UTF-8 password encoding; computed with WebCrypto and Python hashlib.
        assertEquals(
            "13a32f517deeca0f7dd5f6222035b30722cd5c2d6fd48b6104b9dfd2d744e95c",
            deriveAuthSecret("pässwörd-密码-🔑", "AAECAwQFBgcICQoLDA0ODw==", 100_000),
        )
    }

    private val json = Json { ignoreUnknownKeys = true }
    private val challenge by lazy { json.decodeFromString<PowChallenge>(powChallenge) }

    @Test
    fun solvePow_matchesServerAndBrowser() = runBlocking {
        assertEquals(powToken, solvePow(challenge, json))
        // The answer lies outside a smaller search space, and the algorithm is fixed.
        assertNull(solvePow(challenge.copy(maxnumber = 3140), json))
        assertNull(solvePow(challenge.copy(algorithm = "SHA-1"), json))
    }

    @Test
    fun solvePow_refusesSaltsOutsideTheServerFormat() = runBlocking {
        // Solvable at number 0, so only the format check can return null.
        fun solvableAtZero(salt: String) = challenge.copy(salt = salt, challenge = sha256Hex(salt + "0"))
        assertNull(solvePow(solvableAtZero("a".repeat(1 shl 20)), json))
        assertNull(solvePow(solvableAtZero("A".repeat(32)), json))
        assertEquals(0, solvedNumber(solvePow(solvableAtZero("a".repeat(32)), json)!!))
    }

    @Test
    fun solvePow_stopsWhenCancelled() {
        // No answer in range: without a cancellation check this would return null, not throw.
        val unsolvable = challenge.copy(challenge = "0".repeat(64), maxnumber = 100_000)
        var outcome: Result<String?>? = null
        runBlocking {
            launch {
                coroutineContext.job.cancel()
                outcome = runCatching { solvePow(unsolvable, json) }
            }
        }
        assertTrue(outcome!!.exceptionOrNull() is CancellationException)
    }

    private fun sha256Hex(s: String) =
        MessageDigest.getInstance("SHA-256").digest(s.toByteArray()).joinToString("") { "%02x".format(it) }

    private fun solvedNumber(token: String) =
        Regex("\"number\":(\\d+)").find(String(Base64.getDecoder().decode(token)))!!.groupValues[1].toInt()

    @Test
    fun mint_sendsOnlyTheAuthSecret() = runBlocking {
        val factory = relay(captchaProvider = "")
        val r = PasswordPairingClient(factory).mint(server, " play-review ", password) as PairingParseResult.Success
        assertEquals("tok", r.pairing.pairingToken)
        assertEquals(
            listOf("/api/auth/captcha-config", "/api/auth/login-params?username=play-review", "/api/notifications/review-pairing"),
            factory.requests.map { it.url.toString().removePrefix(server) },
        )
        assertEquals("""{"username":"play-review","authSecret":"$sharedVector"}""", factory.bodies.last())
        assertFalse(factory.bodies.any { password in it })
    }

    @Test
    fun mint_solvesTheProofOfWork() = runBlocking {
        val factory = relay(captchaProvider = "pow")
        assertTrue(PasswordPairingClient(factory).mint(server, "play-review", password) is PairingParseResult.Success)
        assertEquals("/api/auth/pow-challenge", factory.requests[2].url.encodedPath)
        assertEquals("""{"username":"play-review","authSecret":"$sharedVector","captchaToken":"$powToken"}""", factory.bodies.last())
    }

    @Test
    fun mint_refusesThirdPartyCaptchaBeforeSendingAnything() = runBlocking {
        val factory = relay(captchaProvider = "turnstile")
        val r = PasswordPairingClient(factory).mint(server, "u", password) as PairingParseResult.Error
        assertTrue(r.reason.contains("CAPTCHA_PROVIDER=pow"))
        assertEquals(1, factory.requests.size)
    }

    @Test
    fun mint_refusesWeakWorkFactorWithoutPosting() = runBlocking {
        val factory = relay(captchaProvider = "", params = """{"salt":"$zeroSalt","iterations":1000}""")
        assertTrue(PasswordPairingClient(factory).mint(server, "u", password) is PairingParseResult.Error)
        assertEquals(2, factory.requests.size)
    }

    @Test
    fun mint_namesAFailedSecurityCheck() = runBlocking {
        val factory = BodyRecordingCallFactory { req ->
            when (req.url.encodedPath) {
                "/api/auth/captcha-config" -> response(req, """{"provider":"pow"}""", 200)
                "/api/auth/login-params" -> response(req, """{"salt":"$zeroSalt","iterations":100000}""", 200)
                "/api/auth/pow-challenge" -> response(req, powChallenge, 200)
                else -> response(req, "your network address changed during the security check, please try again\n", 401)
            }
        }
        val r = PasswordPairingClient(factory).mint(server, "u", password) as PairingParseResult.Error
        assertEquals("The security check failed. Try again", r.reason)
    }

    /** RFC 5869 Test Case 1 — an independent vector, so this confirms the HKDF agrees with the
     *  standard rather than merely round-tripping through itself. */
    @Test
    fun hkdf_matchesRfc5869TestCase1() {
        val okm = hkdfSha256(
            ikm = ByteArray(22) { 0x0b },
            salt = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12),
            info = byteArrayOf(
                0xf0.toByte(), 0xf1.toByte(), 0xf2.toByte(), 0xf3.toByte(), 0xf4.toByte(),
                0xf5.toByte(), 0xf6.toByte(), 0xf7.toByte(), 0xf8.toByte(), 0xf9.toByte(),
            ),
            length = 42,
        )

        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.joinToString("") { "%02x".format(it) },
        )
    }

    /** RFC 5869's ceiling: the block counter is ONE byte, so at 256 blocks it would wrap and
     *  repeat round 1's output. */
    @Test
    fun hkdfRefusesLengthsPastTheOneByteCounter() {
        assertFailsWith<IllegalArgumentException> { hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32 + 1) }
        assertFailsWith<IllegalArgumentException> { hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 0) }
        assertEquals(255 * 32, hkdfSha256(ByteArray(32), ByteArray(32), ByteArray(4), 255 * 32).size)
    }
}
