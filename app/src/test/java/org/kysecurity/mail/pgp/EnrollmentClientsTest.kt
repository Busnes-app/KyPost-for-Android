package org.kysecurity.mail.pgp

import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class EnrollmentClientsTest {

    @Test
    fun publishKey_sendsDeviceHeadersAndTheKey() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.publishKey("https://relay.example.com/", "dev-1", "secret-1", "BASE64KEY")

        assertEquals(EnrollmentCallResult.Ok, result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-key", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("dev-1", sent.header("X-Kypost-Device-Id"))
        assertEquals("secret-1", sent.header("X-Kypost-Device-Secret"))
        val body = okio.Buffer().also { sent.body!!.writeTo(it) }.readUtf8()
        assertTrue("the key must actually be sent: $body", body.contains("\"publicKey\":\"BASE64KEY\""))
    }

    /** Omitting the list resets the claim to [2], after which the browser refuses to seal v3.
     *  Server E2E_PGP.md: "Only advertise v3 after native complete-ring persistence checks pass",
     *  which #112, #115 and #116 did. */
    @Test
    fun publishKey_advertisesVersions2And3() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }

        EnrollmentClients(callFactory = factory).publishKey("https://relay.example.com", "d", "s", "K")

        val body = okio.Buffer().also { factory.requests.single().body!!.writeTo(it) }.readUtf8()
        assertTrue(body, body.contains("\"envelopeVersions\":[2,3]"))
    }

    /** The delivery metadata the server records beside the envelope; the ceremony validates the
     *  ring it opens against exactly these values. */
    @Test
    fun fetchEnvelope_carriesTheDeliveryMetadata() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(
                req,
                """{"slot":"device:dev-1","envelope":"ENV","version":3,"fingerprint":"5F117951610CAF01500FA059CDE63F0EBEC934A2",
                   "materialGeneration":2,"pgpRevision":7,
                   "keyring":{"version":1,"materialGeneration":2,"primaryFingerprints":["A","B"],"keyFingerprints":["A","B","C"]},
                   "publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----"}""",
                200,
            )
        }

        val result = EnrollmentClients(callFactory = factory).fetchEnvelope("https://relay.example.com", "d", "s")

        assertEquals(
            EnrollmentCallResult.Envelope(
                "ENV",
                DeliveryMetadata(
                    version = 3,
                    fingerprint = "5F117951610CAF01500FA059CDE63F0EBEC934A2",
                    materialGeneration = 2L,
                    primaryFingerprints = listOf("A", "B"),
                    keyFingerprints = listOf("A", "B", "C"),
                ),
            ),
            result,
        )
    }

    /** A legacy delivery has no generation and a null keyring; the fields are absent, not zero. */
    @Test
    fun fetchEnvelope_legacyDeliveryHasNoGeneration() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"envelope":"ENV","version":2,"fingerprint":"AB","pgpRevision":1,"keyring":null,"publicKey":""}""", 200)
        }

        val result = EnrollmentClients(callFactory = factory).fetchEnvelope("https://relay.example.com", "d", "s")

        assertEquals(EnrollmentCallResult.Envelope("ENV", DeliveryMetadata(2, "AB", null, null, null)), result)
    }

    @Test
    fun reportState_keyringAcknowledgementNamesVersionGenerationAndFingerprint() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }

        EnrollmentClients(callFactory = factory).reportState(
            "https://relay.example.com", "d", "s",
            EnrollmentReport.Keyring(materialGeneration = 2L, fingerprint = "5F117951610CAF01500FA059CDE63F0EBEC934A2"),
        )

        val body = okio.Buffer().also { factory.requests.single().body!!.writeTo(it) }.readUtf8()
        assertEquals(
            """{"encryptionEnrolled":true,"envelopeVersion":3,"materialGeneration":2,"fingerprint":"5F117951610CAF01500FA059CDE63F0EBEC934A2"}""",
            body,
        )
    }

    /** A bare true is what a legacy account accepts; a converted one refuses it with 409. The
     *  three metadata fields go together, so none of them may leak into the legacy body. */
    @Test
    fun reportState_legacyBodyIsTheBareBoolean() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }

        EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", EnrollmentReport.Legacy)

        val body = okio.Buffer().also { factory.requests.single().body!!.writeTo(it) }.readUtf8()
        assertEquals("""{"encryptionEnrolled":true}""", body)
    }

    /** The server records nothing on 409 and returns the current values; the same claim cannot
     *  become true later, so this is its own result rather than a retryable failure. */
    @Test
    fun reportState_mapsConflict() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"error":"...","pgpStateChanged":true,"materialGeneration":3,"fingerprint":"AB"}""", 409)
        }

        assertEquals(
            EnrollmentCallResult.Conflict,
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", EnrollmentReport.Legacy),
        )
    }

    /** No slot parameter exists on this route — the server builds it from the verified credential.
     *  A client that invented one would be coding against a contract that does not exist. */
    @Test
    fun fetchEnvelope_takesNoSlotParameter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"slot":"device:dev-1","envelope":"ENV"}""", 200)
        }
        val clients = EnrollmentClients(callFactory = factory)

        val result = clients.fetchEnvelope("https://relay.example.com", "dev-1", "secret-1")

        assertEquals(EnrollmentCallResult.Envelope("ENV"), result)
        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/envelope", sent.url.toString())
        assertTrue("no query string may be sent", sent.url.querySize == 0)
    }

    /** 404 covers both "never sealed" and "expired", indistinguishable by design. Both mean
     *  re-run the ceremony, so they must map to one result the caller cannot accidentally split. */
    @Test
    fun fetchEnvelope_mapsNotFound() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, """{"error":"no envelope sealed for this device"}""", 404)
        }

        assertEquals(
            EnrollmentCallResult.NotFound,
            EnrollmentClients(callFactory = factory).fetchEnvelope("https://relay.example.com", "d", "s"),
        )
    }

    /** A 200 that carries no envelope is a failure, not an empty success: treating it as one would
     *  hand the ceremony a blank string to open. */
    @Test
    fun fetchEnvelope_refusesAMalformedBody() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"slot":"device:dev-1"}""", 200) }

        assertTrue(
            EnrollmentClients(callFactory = factory)
                .fetchEnvelope("https://relay.example.com", "d", "s") is EnrollmentCallResult.Failed,
        )
    }

    @Test
    fun reportState_sendsTheBooleanAsRequired() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }
        val clients = EnrollmentClients(callFactory = factory)

        clients.reportState("https://relay.example.com", "dev-1", "secret-1", EnrollmentReport.NotEnrolled)

        val sent = factory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/device/enrollment-state", sent.url.toString())
        val body = okio.Buffer().also { sent.body!!.writeTo(it) }.readUtf8()
        assertTrue("must state an opinion explicitly: $body", body.contains("\"encryptionEnrolled\":false"))
    }

    /** Treated exactly as MfaResponseClient treats it — both come from the same shared
     *  writeDeviceAuthFailure on the server. */
    @Test
    fun rateLimited_carriesRetryAfter() = runBlocking {
        val factory = FakeCallFactory { req ->
            response(req, "", 429, headers = mapOf("Retry-After" to "42"))
        }

        assertEquals(
            EnrollmentCallResult.RateLimited(42L),
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", EnrollmentReport.Legacy),
        )
    }

    @Test
    fun unauthorized_isDistinctFromAGenericFailure() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, "", 401) }

        assertEquals(
            EnrollmentCallResult.Unauthorized,
            EnrollmentClients(callFactory = factory).reportState("https://relay.example.com", "d", "s", EnrollmentReport.Legacy),
        )
    }

    /** The endpoint is built from the paired origin. A URL that could not have come from a pairing
     *  must not reach the network carrying this device's credential. */
    @Test
    fun aNonHttpsServerUrlIsRefusedBeforeAnyCallIsMade() = runBlocking {
        val factory = FakeCallFactory { req -> response(req, """{"ok":true}""", 200) }

        val result = EnrollmentClients(callFactory = factory)
            .reportState("http://relay.example.com", "d", "s", EnrollmentReport.Legacy)

        assertTrue(result is EnrollmentCallResult.Failed)
        assertTrue("no request may be sent", factory.requests.isEmpty())
    }
}
