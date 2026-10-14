package org.kysecurity.mail.push

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.response

class PasswordPairingClientTest {
    private val server = "https://mail.example.com"
    private val password = "correct-horse-battery-staple"
    private val zeroSalt = "AAAAAAAAAAAAAAAAAAAAAA=="

    // KyPost-Server users.TestDeriveAuthSecretMatchesTheBrowser; also reproduced with WebCrypto.
    private val sharedVector = "da9fc5d333fdab121f3c302b6191b68657bf806030a32c0cbd47b39b720dc860"

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
    fun mint_sendsOnlyTheAuthSecret() = runBlocking {
        val link = "kypost://native-pair?sub=s1&srv=https%3A%2F%2Fmail.example.com&reg=https%3A%2F%2Fmail.example.com%2Fapi%2Fnotifications%2Fnative%2Fregister&pt=tok"
        val factory = BodyRecordingCallFactory { req ->
            if (req.url.encodedPath == "/api/auth/login-params") response(req, """{"salt":"$zeroSalt","iterations":100000}""", 200)
            else response(req, """{"deepLink":"$link"}""", 200)
        }
        val r = PasswordPairingClient(factory).mint(server, " play-review ", password) as PairingParseResult.Success
        assertEquals("tok", r.pairing.pairingToken)
        assertEquals("$server/api/auth/login-params?username=play-review", factory.requests[0].url.toString())
        assertEquals("$server/api/notifications/review-pairing", factory.requests[1].url.toString())
        assertEquals("""{"username":"play-review","authSecret":"$sharedVector"}""", factory.bodies[1])
        assertFalse(factory.bodies.any { password in it })
    }

    @Test
    fun mint_refusesWeakWorkFactorWithoutPosting() = runBlocking {
        val factory = BodyRecordingCallFactory { req -> response(req, """{"salt":"$zeroSalt","iterations":1000}""", 200) }
        assertTrue(PasswordPairingClient(factory).mint(server, "u", password) is PairingParseResult.Error)
        assertEquals(1, factory.requests.size)
    }
}
