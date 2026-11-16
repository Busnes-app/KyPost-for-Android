package org.kysecurity.mail.push

import kotlinx.coroutines.runBlocking
import okhttp3.Call
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.kysecurity.mail.security.SpkiPinner
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import org.kysecurity.mail.testing.testTlsHandshake
import javax.net.ssl.SSLPeerUnverifiedException

/** The two places the rollover meets the rest of the app: a resync teaches the pin its key, and
 *  the pinned client retries once after a pin failure the rollover repaired. */
class TlsPinRolloverWiringTest {

    private val leaf by lazy { SpkiPinner.pinFor(testTlsHandshake.peerCertificates.first()) }
    private val pairing = PairingData(
        subscriberId = "sub",
        serverUrl = "https://relay.example.com",
        registrationUrl = "https://relay.example.com/api/notifications/native/register",
        pairingToken = "tok",
        deviceId = "dev",
        deviceSecret = "secret",
        pairedAtEpochMs = 0L,
    )

    private fun resync(store: FakePushStore, key: String?) = runBlocking {
        val keyField = key?.let { ""","relayIdentityKey":"$it"""" }.orEmpty()
        PushSyncCoordinator(
            repository = store,
            registrationClient = NativeRegistrationClient(
                callFactory = FakeCallFactory { req ->
                    response(req, """{"ok":true,"transport":"fcm"$keyField}""", 200, tlsHandshake = testTlsHandshake)
                },
            ),
            wipeOnIncompletePurge = {},
            wipeOwed = { false },
            fetchRegistrationCredential = { PushRegistrationCredential(token = "fcm-token") },
            deregisterReplaced = {},
            capturePinBaseline = { pin, _ -> pin.copy(statementIssuedAt = 1700000000L) },
        ).syncProvidedToken("fcm-token")
    }

    @Test
    fun aPinnedResyncTeachesTheKeyAndAnOlderServerNeverErasesIt() {
        val store = FakePushStore(pairing = pairing).apply { storedPin = TlsPin("relay.example.com", setOf(leaf)) }
        resync(store, KEY)
        assertEquals(TlsPin("relay.example.com", setOf(leaf), KEY, 1700000000L), store.storedPin)
        resync(store, null)
        assertEquals(KEY, store.storedPin?.relayIdentityKey)
    }

    @Test
    fun aMalformedKeyIsNotLearned() {
        val store = FakePushStore(pairing = pairing).apply { storedPin = TlsPin("relay.example.com", setOf(leaf)) }
        resync(store, "c2hvcnQ=")
        assertEquals(null, store.storedPin?.relayIdentityKey)
    }

    private val failing = TlsPin("relay.example.com", setOf("sha256/old"), KEY)
    private val renewed = TlsPin("relay.example.com", setOf("sha256/new"), KEY)

    /** A real client whose next hop fails the way `CertificatePinner` does. */
    private fun pinnedClient(rollover: TlsPinRollover, provider: () -> Pair<TlsPin, Call.Factory>?) =
        OkHttpClient.Builder()
            .addInterceptor(TlsPinRolloverInterceptor(failing, rollover, provider))
            .addInterceptor { throw SSLPeerUnverifiedException("Certificate pinning failure!") }
            .build()

    private fun rollover(current: () -> TlsPin?) =
        TlsPinRollover(current, { _, _ -> false }, { "https://relay.example.com" }, FakeCallFactory { fail("no fetch expected"); throw IllegalStateException() })

    private val request = Request.Builder().url("https://relay.example.com/api/inbox").build()

    @Test
    fun aRepairedPinIsRetriedOnceThroughTheNewClient() {
        val retried = FakeCallFactory { response(it, "{}", 200) }
        val client = pinnedClient(rollover { renewed }) { renewed to retried }
        client.newCall(request).execute().use { assertEquals(200, it.code) }
        assertEquals(listOf(request.url), retried.requests.map { it.url })
    }

    @Test
    fun anUnrepairedPinFailsClosed() {
        val client = pinnedClient(rollover { null }) { fail("no retry"); null }
        try {
            client.newCall(request).execute()
            fail("expected the pin failure")
        } catch (_: SSLPeerUnverifiedException) {
        }
    }

    @Test
    fun theRetryIsNeverRolledAgain() {
        var rolls = 0
        val rollover = TlsPinRollover({ rolls++; renewed }, { _, _ -> false }, { "https://relay.example.com" })
        lateinit var provider: () -> Pair<TlsPin, Call.Factory>?
        // The retried client fails its pin too; a second rollover would loop on a flapping relay.
        provider = { renewed to pinnedClient(rollover, provider) }
        try {
            pinnedClient(rollover, provider).newCall(request).execute()
            fail("expected the pin failure")
        } catch (_: SSLPeerUnverifiedException) {
        }
        assertTrue("rolled $rolls times", rolls == 1)
    }

    private companion object {
        const val KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
    }
}
