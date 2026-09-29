package org.kysecurity.mail.signon

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.push.PairingParseResult
import org.kysecurity.mail.testing.BodyRecordingCallFactory
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response

class KyIdentitySignOnClientTest {
    private val server = "https://mail.example.com"

    @Test
    fun config_ready() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"enabled":true,"issuerUrl":"https://id.example.com/","clientId":"kypost"}""", 200) }
        val r = KyIdentitySignOnClient(factory).config(server) as SignOnConfigResult.Ready
        assertEquals("https://id.example.com", r.config.issuerUrl)
        assertEquals("kypost", r.config.clientId)
        assertEquals("$server/api/auth/sso-config", factory.requests.single().url.toString())
    }

    @Test
    fun config_disabled() = runBlocking {
        val off = FakeCallFactory { req -> response(req, """{"enabled":false,"issuerUrl":""}""", 200) }
        assertTrue(KyIdentitySignOnClient(off).config(server) is SignOnConfigResult.Unavailable)
        val noClient = FakeCallFactory { req -> response(req, """{"enabled":true,"issuerUrl":"https://id.example.com"}""", 200) }
        assertTrue(KyIdentitySignOnClient(noClient).config(server) is SignOnConfigResult.Unavailable)
    }

    @Test
    fun config_rejectsHttpServer() = runBlocking {
        val r = KyIdentitySignOnClient(FakeCallFactory { req -> response(req, "{}", 200) }).config("http://mail.example.com")
        assertTrue(r is SignOnConfigResult.Unavailable)
    }

    @Test
    fun signOn_parsesDeepLink() = runBlocking {
        val link = "kypost://native-pair?sub=s1&srv=https%3A%2F%2Fmail.example.com&reg=https%3A%2F%2Fmail.example.com%2Fapi%2Fnotifications%2Fnative%2Fregister&pt=tok"
        val factory = BodyRecordingCallFactory { req -> response(req, """{"configured":true,"deepLink":"$link"}""", 200) }
        val r = KyIdentitySignOnClient(factory).signOn(server, "eyJ.a.b") as PairingParseResult.Success
        assertEquals("tok", r.pairing.pairingToken)
        assertEquals("$server/api/auth/native/signon", factory.requests.single().url.toString())
        assertEquals("""{"idToken":"eyJ.a.b"}""", factory.bodies.single())
    }

    @Test
    fun signOn_mapsStatuses() = runBlocking {
        suspend fun at(code: Int, body: String = "") = KyIdentitySignOnClient(FakeCallFactory { req -> response(req, body, code) }).signOn(server, "t") as PairingParseResult.Error
        assertTrue(at(503).reason.contains("mail.example.com"))
        assertTrue(at(403, "Access denied: this token was already used.").reason.contains("already used"))
        assertTrue(at(429).reason.contains("Try again"))
        assertTrue(at(200, """{"configured":false,"configurationError":"set PAIRING_SECRET"}""").reason.contains("PAIRING_SECRET"))
    }

    @Test
    fun dtos_redact() {
        assertEquals("SignOnRequest(redacted)", SignOnRequest("secret").toString())
    }
}
