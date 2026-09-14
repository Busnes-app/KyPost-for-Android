package org.kysecurity.mail.pgp

import org.kysecurity.mail.HEADER_DEVICE_ID
import org.kysecurity.mail.HEADER_DEVICE_SECRET
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** `/resolve` answers JSON on 409 and 413 as well as 200, where `/check` is JSON only on 200. */
class RecipientResolveClientTest {

    /** `expired` and `revoked` join the tier set server-side, and more may follow. The client must
     *  carry any tier verbatim and let `usable` decide; a decoder that enumerates tiers would turn
     *  the next server release into a compose-screen outage. */
    @Test
    fun unknownTiersParseAndUsableStillGoverns() = runBlocking {
        val body = """{"results":[
            {"address":"a@example.invalid","publicKey":"K","fingerprint":"AA","tier":"expired","usable":false},
            {"address":"b@example.invalid","publicKey":"K","fingerprint":"BB","tier":"revoked","usable":false},
            {"address":"c@example.invalid","publicKey":"K","fingerprint":"CC","tier":"tier-from-the-future","usable":true}
        ]}"""
        val client = RecipientResolveClient(callFactory = FakeCallFactory { request -> response(request, body, 200) })

        val results = (client.resolve("https://relay.example.com/", "d", "s", listOf("a@example.invalid", "b@example.invalid", "c@example.invalid")) as ResolveResult.Success).results

        assertEquals(listOf("expired", "revoked", "tier-from-the-future"), results.map { it.tier })
        assertEquals(listOf(false, false, true), results.map { it.usable })
    }

    @Test
    fun parsesResolvedKeys() = runBlocking {
        val body = """{"results":[
            {"address":"alice@example.invalid","publicKey":"-----BEGIN PGP PUBLIC KEY BLOCK-----","fingerprint":"AAAA","tier":"contact-verified","usable":true},
            {"address":"bob@example.invalid","tier":"none","usable":false}
        ]}"""
        val callFactory = FakeCallFactory { request -> response(request, body, 200) }
        val client = RecipientResolveClient(callFactory = callFactory)

        val result = client.resolve(
            "https://relay.example.com/",
            "device-1",
            "secret-1",
            listOf("alice@example.invalid", "bob@example.invalid"),
        )

        val results = (result as ResolveResult.Success).results
        assertEquals(2, results.size)
        assertEquals("alice@example.invalid", results[0].address)
        assertTrue(results[0].usable)
        assertEquals("contact-verified", results[0].tier)
        assertEquals("", results[1].publicKey)
        assertTrue("an unusable recipient must not read as usable", !results[1].usable)

        val sent = callFactory.requests.single()
        assertEquals("https://relay.example.com/api/pgp/recipients/resolve", sent.url.toString())
        assertEquals("POST", sent.method)
        assertEquals("device-1", sent.header(HEADER_DEVICE_ID))
        assertEquals("secret-1", sent.header(HEADER_DEVICE_SECRET))
    }

    /** The account is not client-protected, so the server encrypts on its own and this endpoint is
     *  categorically the wrong one. No retry helps, so it must not read as a transport failure. */
    @Test
    fun conflictIsNotClientProtected() = runBlocking {
        val body = """{"error":"this account's PGP key is not client-protected; the server encrypts on its own"}"""
        val client = RecipientResolveClient(callFactory = FakeCallFactory { request -> response(request, body, 409) })

        val result = client.resolve("https://relay.example.com", "d", "s", listOf("a@example.invalid"))

        assertTrue("expected NotClientProtected, got $result", result is ResolveResult.NotClientProtected)
    }

    @Test
    fun payloadTooLargeIsTooMany() = runBlocking {
        val body = """{"error":"too many addresses (maximum 500)"}"""
        val client = RecipientResolveClient(callFactory = FakeCallFactory { request -> response(request, body, 413) })

        val result = client.resolve("https://relay.example.com", "d", "s", listOf("a@example.invalid"))

        assertTrue("expected TooMany, got $result", result is ResolveResult.TooMany)
    }

    /** 400 and 500 are plain text on this endpoint. Running a JSON decoder over them and reporting
     *  "malformed response" would hide a real server error behind a parsing complaint. */
    @Test
    fun plainTextServerErrorIsFailed() = runBlocking {
        val client = RecipientResolveClient(
            callFactory = FakeCallFactory { request -> response(request, "failed to open contacts store", 500) },
        )

        val result = client.resolve("https://relay.example.com", "d", "s", listOf("a@example.invalid"))

        assertTrue("expected Failed, got $result", result is ResolveResult.Failed)
    }

    @Test
    fun emptyAddressListMakesNoRoundTrip() = runBlocking {
        val callFactory = FakeCallFactory { request -> response(request, "{}", 200) }
        val client = RecipientResolveClient(callFactory = callFactory)

        val result = client.resolve("https://relay.example.com", "d", "s", emptyList())

        assertEquals(emptyList<ResolvedRecipientKey>(), (result as ResolveResult.Success).results)
        assertTrue("no addresses is a local answer", callFactory.requests.isEmpty())
    }

    @Test
    fun malformedBodyIsFailed() = runBlocking {
        val client = RecipientResolveClient(callFactory = FakeCallFactory { request -> response(request, "not json", 200) })

        val result = client.resolve("https://relay.example.com", "d", "s", listOf("a@example.invalid"))

        assertTrue("expected Failed, got $result", result is ResolveResult.Failed)
    }
}
