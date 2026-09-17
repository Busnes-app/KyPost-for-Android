package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.util.Base64

class EnrollmentCeremonyExitTest {

    private val fingerprint = FAKE_FINGERPRINT

    private fun portsWithEnvelope(
        sealFor: String = "dev-1",
        aadFingerprint: String = fingerprint,
    ): FakePorts {
        val probe = FakeEnrollmentKeys()
        val envelope = sealEnvelope(probe, sealFor, aadFingerprint)
        return FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Envelope(envelope)))
    }

    @Test
    fun aSealedEnvelopeReachesEnrolled() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(listOf(EnrollmentReport.Legacy), ports.transport.reported)
        assertEquals("the agreement key is spent on success too", 1, ports.keys.deleteCalls)
        assertEquals("no durable fallback was needed", 0, ports.transport.durableReports)
    }

    @Test
    fun theSealerReceivesTheOpenedPlaintext() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertArrayEquals(PLAINTEXT.toByteArray(Charsets.UTF_8), ports.sealer.received.single())
    }

    @Test
    fun thePlaintextIsZeroedInPlaceAfterSealing() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        val handed = ports.sealer.handedArrays.single()
        assertTrue("every byte must be zero", handed.all { it == 0.toByte() })
    }

    @Test
    fun aFailedReportStillMeansEnrolledAndEnqueuesTheWorker() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            reportResult = EnrollmentCallResult.Failed("offline"),
        )

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, ports.transport.durableReports)
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun anEnvelopeSealedForAnotherDeviceIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(sealFor = "some-other-device")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("no second attempt", 1, ports.transport.fetchCalls)
    }

    @Test
    fun anEnvelopeSealedUnderAnotherIdentityIsCouldNotOpen() = runBlocking {
        val ports = portsWithEnvelope(aadFingerprint = "AAAABBBBCCCCDDDD")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
    }

    @Test
    fun anEcdhFailureIsCouldNotOpenAndDestroysTheKeypairWithNoSecondAttempt() = runBlocking {
        val ports = portsWithEnvelope()
        ports.keys.sharedSecretResult = null

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("no second attempt", 1, ports.transport.fetchCalls)
    }

    @Test
    fun aMalformedEnvelopeIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope("""{"v":"1"}""")),
        )

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.ENVELOPE_MALFORMED),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun losingTheLockScreenBeforeTheSealIsItsOwnReason() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.NoSecureLockScreen

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.NO_SECURE_LOCK_SCREEN),
            ports.states.last(),
        )
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aSealFailureIsItsOwnReasonAndDestroysTheKeypair() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Failed("keystore said no")

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.SEAL_FAILED), ports.states.last())
        assertEquals(1, ports.keys.deleteCalls)
    }

    @Test
    fun aCancelledBiometricReturnsToTheCodeWithThePlaintextZeroed() = runBlocking {
        val ports = portsWithEnvelope()
        ports.sealer.outcome = SealOutcome.Cancelled

        lateinit var ceremony: EnrollmentCeremony
        var idleDuringTheWindow: Boolean? = null
        ceremony = EnrollmentCeremony(
            identity = ports.identity,
            transport = ports.transport,
            keys = ports.keys,
            sealer = ports.sealer,
            previousVault = ports.previousVault,
            mailCache = ports.mailCache,
            clock = ports.clock,
            hostileLocationEnabled = { false },
            hasSecureLockScreen = { true },
            onState = { state ->
                ports.states += state
                if (state is EnrollmentUiState.ShowingCode && idleDuringTheWindow == null) {
                    idleDuringTheWindow = ceremony.isIdle
                }
            },
        )

        ceremony.run()

        assertTrue(
            "a dismissed prompt must not send the user back to the code: this path is only reachable " +
                "because the browser already read it and sealed, and the value would go stale on the " +
                "next bucket with no window left to refresh it",
            ports.states.last() is EnrollmentUiState.ReadyToFinish,
        )
        assertTrue(ports.sealer.handedArrays.single().all { it == 0.toByte() })
        assertEquals("a cancel destroys nothing", 0, ports.keys.deleteCalls)
        assertEquals("the window must run with isIdle false", false, idleDuringTheWindow)
        assertTrue("the user must be able to try again", ceremony.isIdle)
    }

    @Test
    fun teardownDestroysALiveKeypairAndIsIdempotent() = runBlocking {
        val ports = FakePorts()
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()
        ceremony.teardown()

        assertEquals(1, ports.keys.deleteCalls)
    }

    /** `EnrollmentTeardown` feeds this boolean to a `SecurityWipe.step`. */
    @Test
    fun teardownAfterABlockedGateDestroysNothing() = runBlocking {
        val ports = FakePorts(identityResult = IdentityCheck.NoIdentity)
        val ceremony = ports.ceremony()
        ceremony.run()

        ceremony.teardown()

        assertEquals(0, ports.keys.deleteCalls)
    }

    /** Exhaustive with no `else`: a new state without a cleanup row is a compile error. */
    private enum class Cleanup {
        DESTROYS_THE_KEYPAIR,
        KEEPS_THE_KEYPAIR,
        NOTHING_WAS_MINTED,

        /** Reaching one of these as a ceremony's last state is itself the bug. */
        NOT_A_TERMINAL_STATE,
    }

    private fun expectedCleanup(state: EnrollmentUiState): Cleanup = when (state) {
        // Transient. A ceremony that stops here has stalled somewhere it must not.
        EnrollmentUiState.CheckingIdentity,
        EnrollmentUiState.PublishingKey,
        EnrollmentUiState.Opening,
        EnrollmentUiState.AwaitingAuth,
        -> Cleanup.NOT_A_TERMINAL_STATE

        // Blocked at the gate: no keypair was ever minted.
        is EnrollmentUiState.Unavailable -> Cleanup.NOTHING_WAS_MINTED

        // The one exit that keeps it — "Check again" resumes against the same key.
        is EnrollmentUiState.WaitingTimedOut -> Cleanup.KEEPS_THE_KEYPAIR

        // A ShowingCode left as the LAST state means a window closed without reaching any exit —
        // the cancelled seal now lands on ReadyToFinish instead, so nothing legitimately stops here.
        is EnrollmentUiState.ShowingCode -> Cleanup.NOT_A_TERMINAL_STATE

        // The cancelled seal. The envelope is already on the relay and the key is what opens it, so
        // "Check again" must find both still in place.
        EnrollmentUiState.ReadyToFinish -> Cleanup.KEEPS_THE_KEYPAIR

        // Success spends the key exactly as failure does. A key that outlives every ceremony is a
        // standing unauthenticated path to every envelope the relay has retained.
        EnrollmentUiState.Enrolled -> Cleanup.DESTROYS_THE_KEYPAIR
        is EnrollmentUiState.Failed -> Cleanup.DESTROYS_THE_KEYPAIR
    }

    @Test
    fun everyTerminalExitMatchesItsRowInTheExitTable() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val cases: List<Pair<String, FakePorts>> = listOf(
            "hostile location" to FakePorts(hostileLocation = true),
            "no lock screen" to FakePorts(secureLockScreen = false),
            "not paired" to FakePorts(deviceIdValue = null),
            "no identity" to FakePorts(identityResult = IdentityCheck.NoIdentity),
            "server-held" to FakePorts(identityResult = IdentityCheck.ServerHeld),
            "could not check" to FakePorts(identityResult = IdentityCheck.CouldNotCheck),
            "publish rejected" to FakePorts(publishResult = EnrollmentCallResult.Failed("no")),
            "publish 401" to FakePorts(publishResult = EnrollmentCallResult.Unauthorized),
            "publish 429" to FakePorts(publishResult = EnrollmentCallResult.RateLimited(1L)),
            "poll timeout" to FakePorts(),
            "poll 401" to FakePorts(fetchResults = mutableListOf(EnrollmentCallResult.Unauthorized)),
            "malformed envelope" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope("nonsense")),
            ),
            "could not open" to FakePorts(
                fetchResults = mutableListOf(
                    EnrollmentCallResult.Envelope(sealEnvelope(probe, deviceId = "elsewhere")),
                ),
            ),
            "success" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            ),
            "report failed" to FakePorts(
                fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
                reportResult = EnrollmentCallResult.Unauthorized,
            ),
        )

        for ((name, ports) in cases) {
            ports.ceremony().run()
            val terminal = ports.states.last()
            val deletions = ports.keys.deleteCalls
            when (expectedCleanup(terminal)) {
                Cleanup.DESTROYS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must destroy the keypair", 1, deletions)
                Cleanup.KEEPS_THE_KEYPAIR ->
                    assertEquals("$name: $terminal must keep the keypair", 0, deletions)
                Cleanup.NOTHING_WAS_MINTED ->
                    assertEquals("$name: blocked at the gate, so there is nothing to destroy", 0, deletions)
                Cleanup.NOT_A_TERMINAL_STATE ->
                    fail("$name: the ceremony stopped in a transient state: $terminal")
            }
        }
    }

    /** Nothing else drops server-decrypted bodies; the delta sync deliberately preserves them. */
    @Test
    fun successDropsThePlaintextTheServerHadDecrypted() = runBlocking {
        val ports = portsWithEnvelope()

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals("the old server-decrypted plaintext must not outlive enrollment", 1, ports.mailCache.clearCalls)
    }

    @Test
    fun thePlaintextIsDroppedEvenWhenTheServerCannotBeTold() = runBlocking {
        val probe = FakeEnrollmentKeys()
        val ports = FakePorts(
            fetchResults = mutableListOf(EnrollmentCallResult.Envelope(sealEnvelope(probe))),
            reportResult = EnrollmentCallResult.Failed("offline"),
        )

        ports.ceremony().run()

        assertEquals(1, ports.mailCache.clearCalls)
    }

    @Test
    fun aFailedCeremonyLeavesTheCacheAlone() = runBlocking {
        val ports = portsWithEnvelope(sealFor = "some-other-device")

        ports.ceremony().run()

        assertEquals(
            EnrollmentUiState.Failed(FailureReason.COULD_NOT_OPEN),
            ports.states.last(),
        )
        assertEquals(0, ports.mailCache.clearCalls)
    }

    @Test
    fun aKeystoreThatCannotMintFailsWithNoDeviceKey() = runBlocking {
        val ports = FakePorts(minting = false)

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.NO_DEVICE_KEY), ports.states.last())
        assertEquals("a failed mint can still leave a key behind", 1, ports.keys.deleteCalls)
        assertEquals("nothing may be published", 0, ports.transport.publishedKeys.size)
    }

    @Test
    fun aKeyWhosePublicHalfCannotBeReadFailsWithNoDeviceKey() = runBlocking {
        val ports = FakePorts()
        ports.keys.encodingFails = true

        ports.ceremony().run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.NO_DEVICE_KEY), ports.states.last())
        assertEquals(1, ports.keys.deleteCalls)
        assertEquals("nothing may be published", 0, ports.transport.publishedKeys.size)
    }

    /** `SecurityWipe` and Hostile Location Protection both destroy the key under a live window. */
    @Test
    fun aKeyDestroyedMidWindowFailsWithNoDeviceKey() = runBlocking {
        val ports = FakePorts()
        lateinit var ceremony: EnrollmentCeremony
        ceremony = EnrollmentCeremony(
            identity = ports.identity,
            transport = ports.transport,
            keys = ports.keys,
            sealer = ports.sealer,
            previousVault = ports.previousVault,
            mailCache = ports.mailCache,
            clock = ports.clock,
            hostileLocationEnabled = { false },
            hasSecureLockScreen = { true },
            onState = { state ->
                ports.states += state
                // Destroy it once the first code is up, so the failure lands on the NEXT boundary —
                // inside the loop, which no canned list of fetch results can reach.
                if (state is EnrollmentUiState.ShowingCode) ports.keys.vanished = true
            },
        )

        ceremony.run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.NO_DEVICE_KEY), ports.states.last())
        assertTrue(
            "the window must stop, not run to its deadline",
            ports.transport.fetchCalls < 100,
        )
    }

    @Test
    fun aKeyDestroyedBeforeTheOpenFailsWithNoDeviceKey() = runBlocking {
        val ports = portsWithEnvelope()
        lateinit var ceremony: EnrollmentCeremony
        ceremony = EnrollmentCeremony(
            identity = ports.identity,
            transport = ports.transport,
            keys = ports.keys,
            sealer = ports.sealer,
            previousVault = ports.previousVault,
            mailCache = ports.mailCache,
            clock = ports.clock,
            hostileLocationEnabled = { false },
            hasSecureLockScreen = { true },
            onState = { state ->
                ports.states += state
                if (state is EnrollmentUiState.Opening) ports.keys.vanished = true
            },
        )

        ceremony.run()

        assertEquals(EnrollmentUiState.Failed(FailureReason.NO_DEVICE_KEY), ports.states.last())
        assertTrue("nothing may be sealed", ports.sealer.received.isEmpty())
    }

    private companion object {
        const val PLAINTEXT = FAKE_PLAINTEXT
    }
}
