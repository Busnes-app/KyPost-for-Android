package org.kysecurity.mail.push

import org.kysecurity.mail.OfflineCall
import okhttp3.Call
import okhttp3.Request
import okhttp3.Response
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import javax.net.ssl.SSLPeerUnverifiedException

class PinnedOrFallbackCallFactoryTest {

    private val request = Request.Builder().url("https://relay.example/api/inbox").build()

    private class RecordingFactory : Call.Factory {
        var calls = 0
        override fun newCall(request: Request): Call {
            calls++
            return NoopCall(request)
        }
    }

    private class NoopCall(private val request: Request) : OfflineCall(request) {
        override fun execute(): Response = throw UnsupportedOperationException()
        override fun enqueue(responseCallback: okhttp3.Callback) = Unit
        override fun cancel() = Unit
        override fun isExecuted() = false
        override fun isCanceled() = false
        override fun clone(): Call = NoopCall(request)
    }

    @Test
    fun usesThePinnedClientWhenAPinExists() {
        val pinned = RecordingFactory()
        val fallback = RecordingFactory()
        val pin = TlsPin("relay.example", setOf("sha256/x"))
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { pin to pinned },
            pinStateProvider = { TlsPinState.Pinned(pin) },
            fallback = fallback,
        )

        factory.newCall(request)

        assertSame(1, pinned.calls)
        assertSame(0, fallback.calls)
    }

    /** A pinned client pins the ONE host it was built for; `CertificatePinner` passes every other
     *  host vacuously. So a request that does not match the pin must be refused rather than sent
     *  with this device's credentials on plain system trust — the state a re-pair racing an
     *  in-flight call used to be able to produce. */
    @Test
    fun refusesARequestForAHostThePinDoesNotCover() {
        val pinned = RecordingFactory()
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { TlsPin("other-relay.example", setOf("sha256/x")) to pinned },
            pinStateProvider = { TlsPinState.Pinned(TlsPin("other-relay.example", setOf("sha256/x"))) },
            fallback = fallback,
        )

        val call = factory.newCall(request)

        assertThrows(SSLPeerUnverifiedException::class.java) { call.execute() }
        assertSame("the mismatched pinned client must not be used", 0, pinned.calls)
        assertSame("and it must not fall through to the unpinned client", 0, fallback.calls)
    }

    /** A `pin` in the pairing link narrows the TOFU window to one key for the one request that
     *  discloses the pairing token, so the fallback must not see it at all. */
    @Test
    fun aLinkPinReplacesTheUnpinnedFallbackBeforeTheFirstPairing() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.NeverPaired },
            fallback = fallback,
        )
        val pinnedRequest = Request.Builder()
            .url("https://relay.example/api/register")
            .tag(
                org.kysecurity.mail.LinkPin::class.java,
                org.kysecurity.mail.LinkPin("relay.example", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            )
            .build()

        val call = factory.newCall(pinnedRequest)

        assertSame(0, fallback.calls)
        // A refusal is the private FailedCall; a real OkHttp client hands back RealCall.
        assertEquals("RealCall", call.javaClass.simpleName)
        assertSame(pinnedRequest, call.request())
    }

    /** A link cannot re-authorise a server whose captured pin has gone missing. */
    @Test
    fun aLinkPinDoesNotRescueALostPin() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.Lost },
            fallback = fallback,
        )
        val pinnedRequest = Request.Builder()
            .url("https://relay.example/api/register")
            .tag(
                org.kysecurity.mail.LinkPin::class.java,
                org.kysecurity.mail.LinkPin("relay.example", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            )
            .build()

        assertThrows(SSLPeerUnverifiedException::class.java) { factory.newCall(pinnedRequest).execute() }
        assertSame(0, fallback.calls)
    }

    /** The legitimate TOFU window: pairing itself cannot be pinned, because the pin comes from it. */
    @Test
    fun fallsBackUnpinnedOnlyBeforeTheFirstPairing() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.NeverPaired },
            fallback = fallback,
        )

        factory.newCall(request)

        assertSame(1, fallback.calls)
    }

    @Test
    fun refusesRatherThanDowngradingWhenAPinWasLost() {
        val fallback = RecordingFactory()
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.Lost },
            fallback = fallback,
        )

        val call = factory.newCall(request)

        assertSame("the unpinned client must not be reached", 0, fallback.calls)
        assertThrows(SSLPeerUnverifiedException::class.java) { call.execute() }
    }

    @Test
    fun aRefusalReachesTheEnqueueCallbackAsAFailure() {
        val factory = PinnedOrFallbackCallFactory(
            pinnedProvider = { null },
            pinStateProvider = { TlsPinState.Lost },
            fallback = RecordingFactory(),
        )
        var failure: Throwable? = null

        factory.newCall(request).enqueue(object : okhttp3.Callback {
            override fun onFailure(call: Call, e: java.io.IOException) { failure = e }
            override fun onResponse(call: Call, response: Response) = Unit
        })

        assertTrue("expected an IOException, got $failure", failure is SSLPeerUnverifiedException)
    }
}
