package org.kysecurity.mail.push

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response

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

    @Test
    fun solvePow_matchesServerAndBrowser() {
        val json = Json { ignoreUnknownKeys = true }
        val challenge = json.decodeFromString<PowChallenge>(powChallenge)
        assertEquals(powToken, solvePow(challenge, json))
        // The answer lies outside a smaller search space, and the algorithm is fixed.
        assertNull(solvePow(challenge.copy(maxnumber = 3140), json))
        assertNull(solvePow(challenge.copy(algorithm = "SHA-1"), json))
    }

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
}
