package org.kysecurity.mail.push

import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import kotlinx.coroutines.runBlocking
import org.kysecurity.mail.security.SpkiPinner
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import org.kysecurity.mail.testing.testTlsHandshake
import java.util.Base64

class TlsPinRolloverTest {

    // KyPost-Server `TestTLSPinStatementVector`: same seed, statement and signature. A format
    // change on either side breaks one of the two tests.
    @Test
    fun verifiesTheServersVector() {
        assertTrue(verifyTlsPinStatement(VECTOR_KEY, VECTOR_HOST, VECTOR_PIN, VECTOR_AT, VECTOR_SIG))
        assertFalse(verifyTlsPinStatement(VECTOR_KEY, "evil.example.com", VECTOR_PIN, VECTOR_AT, VECTOR_SIG))
        assertFalse(verifyTlsPinStatement(VECTOR_KEY, VECTOR_HOST, OTHER_PIN, VECTOR_AT, VECTOR_SIG))
        assertFalse(verifyTlsPinStatement(VECTOR_KEY, VECTOR_HOST, VECTOR_PIN, VECTOR_AT + 1, VECTOR_SIG))
        assertFalse(verifyTlsPinStatement(VECTOR_KEY, VECTOR_HOST, VECTOR_PIN, VECTOR_AT, "not base64!"))
    }

    @Test
    fun onlyA32ByteKeyIsAccepted() {
        assertEquals(VECTOR_KEY, relayIdentityKeyOrNull(VECTOR_KEY))
        assertNull(relayIdentityKeyOrNull(Base64.getEncoder().encodeToString(ByteArray(31))))
        assertNull(relayIdentityKeyOrNull("%%%"))
        assertNull(relayIdentityKeyOrNull(null))
    }

    @Test
    fun aSignedRenewedLeafReplacesThePinAndKeepsTheKey() {
        val h = Harness()
        assertTrue(h.rollover.roll(h.stored))
        assertEquals(TlsPin(HOST, setOf(observed), VECTOR_KEY, NOW), h.saved)
        val request = h.fetcher.requests.single()
        assertEquals("https://$HOST/kypost/api/notifications/native/tls-pin", request.url.toString())
        assertTrue("the fetch is unpinned and must carry no credential", request.headers.names().none { it.startsWith("X-Kypost", ignoreCase = true) })
    }

    @Test
    fun aRelayedStatementForAnotherLeafIsRefused() {
        // An interceptor shows its own leaf (observed) while relaying the relay's real statement.
        val h = Harness(statementPin = OTHER_PIN)
        assertFalse(h.rollover.roll(h.stored))
        assertNull(h.saved)
    }

    @Test
    fun aStaleStatementIsRefused() {
        val h = Harness(issuedAt = NOW - STATEMENT_MAX_SKEW_SECONDS - 1)
        assertFalse(h.rollover.roll(h.stored))
        assertNull(h.saved)
    }

    @Test
    fun aStatementNoNewerThanTheOneThatInstalledThePinIsRefused() {
        // A replayed statement for a retired leaf is never newer than the rollover that retired it.
        val h = Harness(storedIssuedAt = NOW)
        assertFalse(h.rollover.roll(h.stored))
        assertNull(h.saved)
    }

    @Test
    fun anUnpairDuringTheFetchIsNotUndone() {
        val h = Harness()
        h.beforeSave = { h.current = null }
        assertFalse(h.rollover.roll(h.stored))
        assertNull(h.saved)
    }

    @Test
    fun aStatementForAnotherHostIsRefused() {
        val h = Harness(statementHost = "other.example.com")
        assertFalse(h.rollover.roll(h.stored))
    }

    @Test
    fun aSignatureByAnotherKeyIsRefused() {
        val h = Harness(signingSeed = 2)
        assertFalse(h.rollover.roll(h.stored))
    }

    @Test
    fun withoutAKeyNothingIsFetched() {
        val h = Harness(storedKey = null)
        assertFalse(h.rollover.roll(h.stored))
        assertTrue(h.fetcher.requests.isEmpty())
    }

    @Test
    fun theLeafAlreadyPinnedIsNotARollover() {
        // The pin failure was something else; replacing the pin with itself would retry forever.
        val h = Harness(storedPins = setOf(observed))
        assertFalse(h.rollover.roll(h.stored))
        assertNull(h.saved)
    }

    @Test
    fun aPinAlreadyReplacedByAnotherCallerIsRetriedWithoutAFetch() {
        val h = Harness()
        val newer = TlsPin(HOST, setOf(OTHER_PIN), VECTOR_KEY)
        h.current = newer
        assertTrue(h.rollover.roll(h.stored))
        assertTrue(h.fetcher.requests.isEmpty())
    }

    @Test
    fun aCapturedPinWithoutAnAuthenticatedReplayFloorCannotRoll() {
        val h = Harness(storedIssuedAt = 0)
        assertFalse(h.rollover.roll(h.stored))
        assertTrue(h.fetcher.requests.isEmpty())
    }

    @Test
    fun authenticatedCurrentLeafEstablishesTheFloorBeforeRollover() = runBlocking {
        val capture = Harness(storedPins = setOf(observed), storedIssuedAt = 0)
        val pinned = captureTlsPinBaseline(capture.stored, "https://$HOST", capture.fetcher) { NOW }
        assertEquals(NOW, pinned.statementIssuedAt)
        val retired = Harness(issuedAt = NOW - 1, storedIssuedAt = pinned.statementIssuedAt)
        assertFalse(retired.rollover.roll(retired.stored))
        assertNull(retired.saved)
    }

    @Test
    fun anotherLeafCannotEstablishTheReplayFloor() = runBlocking {
        val capture = Harness(storedIssuedAt = 0)
        val pinned = captureTlsPinBaseline(capture.stored, "https://$HOST", capture.fetcher) { NOW }
        assertEquals(0L, pinned.statementIssuedAt)
    }

    private class Harness(
        statementPin: String? = null,
        statementHost: String = HOST,
        issuedAt: Long = NOW,
        signingSeed: Int = 1,
        storedKey: String? = VECTOR_KEY,
        storedPins: Set<String> = setOf(VECTOR_PIN),
        storedIssuedAt: Long = NOW - 1,
    ) {
        val stored = TlsPin(HOST, storedPins, storedKey, storedIssuedAt)
        var current: TlsPin? = stored
        /** Runs inside the compare-and-swap, before the compare: where a concurrent unpair lands. */
        var beforeSave: () -> Unit = {}
        var saved: TlsPin? = null
        val fetcher = FakeCallFactory { request ->
            val pin = statementPin ?: observed
            val signature = sign(signingSeed, statementHost, pin, issuedAt)
            response(
                request,
                """{"host":"$statementHost","pin":"$pin","issuedAt":$issuedAt,"signature":"$signature"}""",
                200,
                tlsHandshake = testTlsHandshake,
            )
        }
        val rollover = TlsPinRollover(
            currentPin = { current },
            replacePin = { expected, new ->
                beforeSave()
                if (current != expected) {
                    false
                } else {
                    saved = new
                    current = new
                    true
                }
            },
            serverUrl = { "https://$HOST/kypost" },
            fetcher = fetcher,
            nowEpochSeconds = { NOW },
        )
    }

    private companion object {
        const val HOST = "relay.example.com"
        const val NOW = 1_700_000_000L
        const val VECTOR_HOST = "relay.example.com"
        const val VECTOR_PIN = "sha256/47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU="
        const val VECTOR_AT = 1_700_000_000L
        const val VECTOR_KEY = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w="
        const val VECTOR_SIG = "4Y5/TW0bEWsuVlekoKXVqA0lkRT3MSDzepeAf8Ts+jaogUE7EBwkEyiowiwIP8vcf4zIB2oa2btKzOgumbphAA=="
        const val OTHER_PIN = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

        val observed: String by lazy { SpkiPinner.pinFor(testTlsHandshake.peerCertificates.first()) }

        fun sign(seed: Int, host: String, pin: String, issuedAt: Long): String {
            val message = "kypost-tls-pin/1\n$host\n$pin\n$issuedAt".toByteArray()
            val signer = Ed25519Signer()
            signer.init(true, Ed25519PrivateKeyParameters(ByteArray(32) { seed.toByte() }, 0))
            signer.update(message, 0, message.size)
            return Base64.getEncoder().encodeToString(signer.generateSignature())
        }
    }
}
