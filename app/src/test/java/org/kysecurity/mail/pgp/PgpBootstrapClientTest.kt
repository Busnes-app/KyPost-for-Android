package org.kysecurity.mail.pgp

import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.mail.replyAllRecipients
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

    /** `suggestedUserIDs[0]` is the server's own `resolveMailFrom` input, so it is authoritative.
     *  A relay before KyPost-Server#453 sends no `accountAddresses`, so own addresses fall back to it. */
    @Test
    fun parsesTheAccountAddressFromSuggestedUserIds() = runBlocking {
        val body = """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["me@example.invalid","alias@example.invalid"]}"""
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val result = client.fetch("https://relay.example.com", "device-1", "secret-1")

        assertEquals("me@example.invalid", (result as PgpBootstrapResult.Success).accountAddress)
        // Every send-as alias, primary first: an RSVP answers as whichever one the invite names.
        assertEquals(listOf("me@example.invalid", "alias@example.invalid"), result.addresses)
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

    /** KyPost-Server#453: the login `demo` is no address, so `accountAddresses` names the real one.
     *  It feeds Reply All only; the delivery `From` stays the relay's own `resolveMailFrom` input. */
    @Test
    fun ownAddressesComeFromAccountAddressesWhenTheRelaySendsThem() = runBlocking {
        val result = fetch(
            """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["demo"],""" +
                """"accountAddresses":["demo@kypost-demo.local","alias@example.invalid"]}""",
        )

        assertEquals(listOf("demo@kypost-demo.local", "alias@example.invalid"), result.addresses)
        assertEquals("demo", result.accountAddress)
    }

    /** Present but empty is that relay's answer (no address is known), not an old relay. */
    @Test
    fun emptyAccountAddressesIsNotAFallbackToSuggestedUserIds() = runBlocking {
        val result = fetch("""{"hasIdentity":true,"suggestedUserIDs":["demo"],"accountAddresses":[]}""")

        assertEquals(emptyList<String>(), result.addresses)
    }

    /** The demo.kypost.org bug: Reply All put `demo@kypost-demo.local` back in Cc. */
    @Test
    fun replyAllOnANewRelayLeavesOutTheRealAddressAndKeepsEveryoneElse() = runBlocking {
        val own = fetch(
            """{"suggestedUserIDs":["demo"],"accountAddresses":["demo@kypost-demo.local","Alias@Example.invalid"]}""",
        ).addresses

        val recipients = replyAllRecipients(
            sender = "Bob <bob@example.invalid>",
            to = listOf("Demo <DEMO@kypost-demo.local>", "carol@example.invalid"),
            cc = listOf("alias@example.invalid", "dave@example.invalid"),
            own = own,
        )

        assertEquals(listOf("bob@example.invalid", "carol@example.invalid", "dave@example.invalid"), recipients)
    }

    /** An old relay's list is the fallback, exactly as before: its address entries are left out. */
    @Test
    fun replyAllOnAnOldRelayFallsBackToSuggestedUserIds() = runBlocking {
        val own = fetch("""{"suggestedUserIDs":["me@example.invalid","alias@example.invalid"]}""").addresses

        val recipients = replyAllRecipients(
            sender = "me@example.invalid",
            to = listOf("bob@example.invalid", "ALIAS@example.invalid"),
            cc = listOf("carol@example.invalid"),
            own = own,
        )

        assertEquals(listOf("bob@example.invalid", "carol@example.invalid"), recipients)
    }

    private suspend fun fetch(body: String): PgpBootstrapResult.Success =
        PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })
            .fetch("https://relay.example.com", "device-1", "secret-1") as PgpBootstrapResult.Success

    @Test
    fun unusableServerUrl_isFailed() = runBlocking {
        val client = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) })

        val result = client.fetch("not a url", "device-1", "secret-1")

        assertTrue("expected Failed, got $result", result is PgpBootstrapResult.Failed)
    }
}
