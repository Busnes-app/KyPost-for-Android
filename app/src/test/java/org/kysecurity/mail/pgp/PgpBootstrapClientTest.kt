package org.kysecurity.mail.pgp

import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.ThrowingCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

class PgpBootstrapClientTest {

    @Test
    fun parsesProtectionAndIdentity() = runBlocking {
        val callFactory = FakeCallFactory { request ->
            response(request, """{"hasIdentity":true,"protection":"client"}""", 200)
        }
        val client = PgpBootstrapClient(callFactory = callFactory)

        val result = client.fetch("https://relay.example.com/", "device-1", "secret-1")

        assertEquals(
            PgpBootstrapResult.Success(hasIdentity = true, protection = "client", publicKey = ""),
            result,
        )
        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/bootstrap", sent.url.toString())
        assertEquals("GET", sent.method)
        assertEquals("device-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /** Bootstrap carries wrappedPrivateKey, unlockRequired, signerPublicKeys, payloadEndpoint and
     *  more, all of which exist for the browser. Unknown fields must not break parsing. */
    @Test
    fun ignoresTheBrowsersFields() = runBlocking {
        val body = """{"hasIdentity":false,"protection":"server","wrappedPrivateKey":"x","unlockRequired":true,"signerPublicKeys":[],"payloadEndpoint":"/x"}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(
            PgpBootstrapResult.Success(hasIdentity = false, protection = "server", publicKey = ""),
            result,
        )
    }

    /** The PGP QR screen shows the user their own fingerprint beside the code they present, and
     *  computes it from these bytes rather than from the response's `fingerprint` claim. */
    @Test
    fun parsesTheOwnPublicKey() = runBlocking {
        val body = """{"hasIdentity":true,"protection":"client","publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----"}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nabc\n-----END PGP PUBLIC KEY BLOCK-----",
            (result as PgpBootstrapResult.Success).publicKey,
        )
    }

    /** A failed bootstrap must be distinguishable from a successful "no identity", or the compose
     *  screen cannot honor couldn't-check-is-not-no. */
    @Test
    fun httpFailure_isFailedNotAnEmptySuccess() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "unavailable", 503) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    /** 503 and 401 bodies are plain text; a decoder run over them must not surface as a parse
     *  error, and a network throw must not escape. */
    @Test
    fun networkThrow_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = ThrowingCallFactory(IOException("no route to host")))

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    @Test
    fun malformedBody_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }

    /** `suggestedUserIDs[0]` is the server's own `resolveMailFrom` input, so it is authoritative. */
    @Test
    fun parsesTheAccountAddressFromSuggestedUserIds() = runBlocking {
        val body = """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["me@example.invalid","alias@example.invalid"]}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals("me@example.invalid", (result as PgpBootstrapResult.Success).accountAddress)
    }

    /** Reply All drops every one of these, verified send-as aliases included. */
    @Test
    fun keepsEveryOwnAddress() = runBlocking {
        val body = """{"hasIdentity":false,"protection":"","suggestedUserIDs":["me@example.invalid","alias@example.invalid"]}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals(
            listOf("me@example.invalid", "alias@example.invalid"),
            (result as PgpBootstrapResult.Success).ownAddresses,
        )
    }

    /** No mail account configured server-side, so there is no valid `From` to build. Compose must
     *  degrade to the webmail handoff rather than offer a send that is guaranteed to 403. */
    @Test
    fun absentSuggestedUserIdsYieldABlankAccountAddress() = runBlocking {
        val client = PgpBootstrapClient(
            callFactory = FakeCallFactory { request ->
                response(request, """{"hasIdentity":true,"protection":"client"}""", 200)
            },
        )

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals("", (result as PgpBootstrapResult.Success).accountAddress)
    }

    @Test
    fun unusableServerUrl_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }
}
