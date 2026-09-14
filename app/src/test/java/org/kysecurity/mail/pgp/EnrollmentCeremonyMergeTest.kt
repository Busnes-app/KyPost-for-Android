package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import org.kysecurity.mail.MemoryBudget

/** Re-enrollment must preserve every key already held by the device or leave its vault untouched. */
class EnrollmentCeremonyMergeTest {

    @After fun clearSession() = EnrollmentSession.clear()

    private fun ports(
        previousVault: VaultOpener,
        plaintext: String = TestPgpSecondKey.ARMORED_PRIVATE,
    ): FakePorts {
        val probe = FakeEnrollmentKeys()
        return FakePorts(
            fetchResults = mutableListOf(
                EnrollmentCallResult.Envelope(sealEnvelope(probe, plaintext = plaintext)),
            ),
            previousVault = previousVault,
        )
    }

    @Test
    fun reEnrollmentSealsAUsableMergedVault() = runBlocking {
        val previous = FakeVaultOpener(keyToHold = TestPgpPrivateKey.ARMORED_PRIVATE)
        val ports = ports(previous)

        ports.ceremony().run()

        val merged = ports.sealer.received.single()
        val mergedChars = merged.toString(Charsets.UTF_8).toCharArray()
        assertEquals(EnrollmentUiState.Enrolled, ports.states.last())
        assertEquals(1, previous.opened)
        assertEquals(2, ringCount(merged))
        assertTrue(
            PgpDecryptor.decrypt(
                mergedChars,
                TestPgpPrivateKey.ARMORED_MESSAGE,
                emptyList(),
            ) is DecryptResult.Ok,
        )

        val signed = PgpEncryptor.encrypt(
            "signed".toByteArray(),
            listOf(TestPgpSecondKey.ARMORED_PUBLIC),
            mergedChars,
        ) as EncryptResult.Ok
        val verified = PgpDecryptor.decrypt(
            mergedChars,
            signed.armored,
            listOf(TestPgpSecondKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok
        assertTrue(verified.signature.valid)
    }

    @Test
    fun aHeldSessionKeyMergesWithoutOpeningAgainAndIsClearedAfterSeal() = runBlocking {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val previous = FakeVaultOpener()
        val ports = ports(previous)
        ports.mailCache.beforeClear = {
            assertFalse("session must clear before later reads", EnrollmentSession.isHeld())
            assertTrue("plaintext must clear before cache work", ports.sealer.handedArrays.single().all { it == 0.toByte() })
        }

        ports.ceremony().run()

        assertEquals(0, previous.opened)
        assertEquals(2, ringCount(ports.sealer.received.single()))
        assertFalse(EnrollmentSession.isHeld())
    }

    @Test
    fun onlyGenuineFirstEnrollmentSealsTheCurrentKeyAlone() = runBlocking {
        val ports = ports(FakeVaultOpener(outcome = OpenOutcome.NotEnrolled))

        ports.ceremony().run()

        assertEquals(1, ringCount(ports.sealer.received.single()))
        assertEquals(listOf(true), ports.transport.reported)
    }

    @Test
    fun cancelledFailedOrLostPreviousVaultNeverGetsOverwrittenOrReported() = runBlocking {
        val cases = listOf(
            FakeVaultOpener(outcome = OpenOutcome.Cancelled) to EnrollmentUiState.ReadyToFinish,
            FakeVaultOpener(outcome = OpenOutcome.Failed("keystore invalidated")) to
                EnrollmentUiState.Failed(FailureReason.SEAL_FAILED),
            FakeVaultOpener(outcome = OpenOutcome.Opened, keyToHold = null) to
                EnrollmentUiState.Failed(FailureReason.SEAL_FAILED),
        )

        cases.forEach { (opener, expectedState) ->
            val ports = ports(opener)
            ports.ceremony().run()

            assertTrue(ports.sealer.received.isEmpty())
            assertTrue(ports.transport.reported.isEmpty())
            assertEquals(expectedState, ports.states.last())
        }
    }

    @Test
    fun transientPreviousVaultFailureRefusesSealingAndCanRetryWithTheHistoricalKey() = runBlocking {
        var unavailable = true
        val previous = object : VaultOpener {
            override suspend fun open(): OpenOutcome {
                if (unavailable) throw org.kysecurity.mail.security.EncryptedStoreUnavailableException(
                    "device_envelope_secure", IllegalStateException("transient test failure"),
                )
                EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
                return OpenOutcome.Opened
            }
        }
        val failed = ports(previous)
        failed.ceremony().run()
        assertTrue(failed.sealer.received.isEmpty())
        assertTrue(failed.transport.reported.isEmpty())
        assertEquals(EnrollmentUiState.Failed(FailureReason.SEAL_FAILED), failed.states.last())

        unavailable = false
        val retry = ports(previous)
        retry.ceremony().run()
        val merged = retry.sealer.received.single().toString(Charsets.UTF_8).toCharArray()
        assertEquals(listOf(true), retry.transport.reported)
        assertTrue(PgpDecryptor.decrypt(merged, TestPgpPrivateKey.ARMORED_MESSAGE, emptyList()) is DecryptResult.Ok)
    }

    @Test
    fun malformedOrOverLimitMergeNeverGetsOverwrittenOrReported() = runBlocking {
        val ring = orderedSecretKeyRings(
            TestPgpPrivateKey.ARMORED_PRIVATE.byteInputStream(),
        )!!.single()
        val excessiveRings = serializeSecretKeyRings(
            List(MemoryBudget.PGP_SECRET_KEY_RING_COUNT + 1) { ring },
        )!!.toString(Charsets.UTF_8)
        val cases = mapOf(
            "invalid current" to ports(FakeVaultOpener(), plaintext = "invalid current"),
            "invalid previous" to ports(FakeVaultOpener(keyToHold = "invalid previous")),
            "too many rings" to ports(FakeVaultOpener(keyToHold = excessiveRings)),
            "previous input too large" to ports(
                FakeVaultOpener(
                    keyToHold = "x".repeat(MemoryBudget.PGP_SECRET_KEY_PREVIOUS_INPUT_BYTES + 1),
                ),
            ),
        )

        cases.forEach { (label, ports) ->
            EnrollmentSession.clear()
            ports.ceremony().run()

            assertTrue(label, ports.sealer.received.isEmpty())
            assertTrue(label, ports.transport.reported.isEmpty())
            assertEquals(label, EnrollmentUiState.Failed(FailureReason.SEAL_FAILED), ports.states.last())
        }
    }

    @Test
    fun currentAndMergedArraysAreZeroedOnEveryExitAfterMerge() = runBlocking {
        val ports = ports(FakeVaultOpener())
        ports.sealer.outcome = SealOutcome.Cancelled

        ports.ceremony().run()

        assertTrue(ports.sealer.handedArrays.single().all { it == 0.toByte() })
        assertTrue(ports.states.last() is EnrollmentUiState.ReadyToFinish)
    }

    @Test
    fun mergedArrayIsZeroedWhenTheSealerThrows() = runBlocking {
        val ports = ports(FakeVaultOpener())
        ports.sealer.failure = IllegalStateException("unexpected sealer failure")

        try {
            ports.ceremony().run()
            fail("expected the fake sealer to throw")
        } catch (_: IllegalStateException) {
            // The production sealer reports failures, but cleanup also covers a broken implementation.
        }

        assertTrue(ports.sealer.handedArrays.single().all { it == 0.toByte() })
        assertTrue(ports.transport.reported.isEmpty())
    }
}
