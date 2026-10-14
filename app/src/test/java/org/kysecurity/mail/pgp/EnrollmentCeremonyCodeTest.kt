package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Base64

class EnrollmentCeremonyCodeTest {

    private fun bucketOf(ports: FakePorts): Long = ports.clock.epochSeconds() / 120L

    /** [FakeEnrollmentKeys] returns different points from `rawPublicKey()` and `encodedPublicKey()`. */
    @Test
    fun theCodeDerivesFromTheKeystoreKeyAndNotFromWhatWasPublished() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        val fromKeystore = deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", bucket)
        assertEquals(fromKeystore, shown.code)

        val published = Base64.getDecoder().decode(ports.transport.publishedKeys.single())
        val fromPublished = deviceEnrollmentCode(published, "dev-1", bucket)
        assertNotEquals(
            "the code must not be derivable from the published value",
            fromPublished,
            shown.code,
        )
    }

    /** Any write to the account's PGP identity clears the stored key server-side. */
    @Test
    fun theKeyIsPublishedOnEveryCeremonyNotOnce() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()
        ports.ceremony().run()

        assertEquals(2, ports.transport.publishedKeys.size)
        assertEquals("each ceremony mints a fresh keypair", 2, ports.keys.newKeyPairCalls)
    }

    /** Three buckets are crossed in a five-minute window (0s, 120s, 240s). */
    @Test
    fun theCodeRecomputesOnTheBucketBoundaryAndNotBefore() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>()
        assertEquals(3, shown.size)
        assertEquals("each bucket gives a different code", 3, shown.map { it.code }.toSet().size)
    }

    /** The countdown has to point at the end of the current bucket, not at a fixed offset. */
    @Test
    fun theExpiryIsTheEndOfTheCurrentBucket() = runBlocking {
        val ports = FakePorts()
        val bucket = bucketOf(ports)

        ports.ceremony().run()

        val shown = ports.states.filterIsInstance<EnrollmentUiState.ShowingCode>().first()
        assertEquals((bucket + 1) * 120L * 1_000L, shown.expiresAtEpochMs)
    }

    /** 300 seconds at 3-second intervals is exactly 100 attempts. */
    @Test
    fun pollingStopsAtTheDeadline() = runBlocking {
        val ports = FakePorts()

        ports.ceremony().run()

        assertEquals(100, ports.transport.fetchCalls)
        assertTrue(ports.states.last() is EnrollmentUiState.WaitingTimedOut)
        assertTrue("every wait is the 3-second interval", ports.clock.sleeps.all { it == 3_000L })
    }

    @Test
    fun aResumedWindowShowsACodeBeforeItPolls() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()

        ceremony.run()
        assertTrue(ports.states.last() is EnrollmentUiState.WaitingTimedOut)

        // Same bucket the window closed in: the clock is not advanced here on purpose.
        val probe = FakeEnrollmentKeys()
        ports.transport.fetchWhenExhausted =
            EnrollmentCallResult.Envelope(sealEnvelope(probe), legacyDelivery())
        val afterTimeout = ports.states.size

        ceremony.checkAgain()

        assertTrue(
            "the resumed window must re-show the code before polling; without poll()'s shownBucket " +
                "reset the screen is left on WaitingTimedOut and jumps straight to ${ports.states[afterTimeout]}",
            ports.states[afterTimeout] is EnrollmentUiState.ShowingCode,
        )
    }

    /** A restart would rotate the key and invalidate a code the user may have already typed. */
    @Test
    fun checkAgainOpensAFreshWindowAgainstTheSameKeypair() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()

        ceremony.run()
        val statesBeforeResume = ports.states.size

        ceremony.checkAgain()

        assertEquals("a second full window ran", 200, ports.transport.fetchCalls)
        assertEquals("the key must not be re-minted", 1, ports.keys.newKeyPairCalls)
        assertEquals("the key must not be republished", 1, ports.transport.publishedKeys.size)

        // The code rotates with the 120-second bucket; what must not change is the key behind it.
        val resumed = ports.states.drop(statesBeforeResume)
            .filterIsInstance<EnrollmentUiState.ShowingCode>()
            .first()
        val resumedBucket = resumed.expiresAtEpochMs / 1_000L / 120L - 1L
        assertEquals(
            "the resumed code must come from the same keypair the user already read",
            deviceEnrollmentCode(ports.keys.keystorePoint, "dev-1", resumedBucket),
            resumed.code,
        )
    }

    /** 404 is "never sealed" and "expired" collapsed into one result by design. Both mean keep
     *  waiting, not fail. */
    @Test
    fun aNotFoundKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.NotFound,
                EnrollmentCallResult.Envelope("{}", legacyDelivery()),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        assertTrue(ports.states.any { it is EnrollmentUiState.Opening })
    }

    @Test
    fun aTransientFailureOrRateLimitKeepsWaiting() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.Failed("connection reset"),
                EnrollmentCallResult.RateLimited(5L),
                EnrollmentCallResult.Envelope("{}", legacyDelivery()),
            ),
        )

        ports.ceremony().run()

        assertEquals(3, ports.transport.fetchCalls)
        assertTrue(
            ports.states.takeWhile { it !is EnrollmentUiState.Opening }
                .none { it is EnrollmentUiState.Failed },
        )
    }

    @Test
    fun a401WhilePollingFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aRejectedPublishFailsAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Failed("boom"))

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.PUBLISH_REJECTED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("nothing may be polled for", 0, ports.transport.fetchCalls)
    }

    @Test
    fun a401OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.Unauthorized)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.UNAUTHORIZED), ports.states.last())
    }

    @Test
    fun a429OnPublishIsItsOwnReason() = runBlocking {
        val ports = FakePorts(publishResult = EnrollmentCallResult.RateLimited(30L))

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.RATE_LIMITED), ports.states.last())
    }
}
