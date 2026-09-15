package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** The local import sequence, against fakes: validate, then replacement safety, then a durable
 *  seal, then the session, then completion. Nothing on any other path. */
class KeyringImportTest {

    private val fixture = SharedFixtures.keyring()
    private val ring = fixture["ring"]!!.jsonObject
    private val ringBytes = ring.toString().toByteArray(Charsets.UTF_8)
    private val active = ring["activeFingerprint"]!!.jsonPrimitive.content

    /** The same keys, one generation later: a valid ring this device cannot prove comparable. */
    private val laterRingBytes = JsonObject(ring + ("materialGeneration" to JsonPrimitive(3))).toString().toByteArray(Charsets.UTF_8)

    private val sealer = FakeVaultSealer()
    private val transport = FakeEnrollmentTransport()
    private val events = mutableListOf<String>()

    @After fun cleanup() = EnrollmentSession.clear()

    private fun opener(outcome: OpenOutcome, key: String? = null) = FakeVaultOpener(outcome, key)

    private suspend fun import(bytes: ByteArray = ringBytes, expected: String = active, opener: VaultOpener) =
        importKeyring(bytes, expected, opener, sealer) { events += "complete" }

    @Test
    fun aFreshImportSealsThenInstallsThenCompletes() = runBlocking {
        sealer.onSeal = { events += "seal(held=${EnrollmentSession.isHeld()})" }

        val outcome = import(opener = opener(OpenOutcome.NotEnrolled))

        assertEquals(KeyringImportOutcome.Imported, outcome)
        assertEquals(listOf("seal(held=false)", "complete"), events)
        assertEquals(listOf(VaultRecordKind.KEYRING), sealer.kinds)
        assertArrayEquals("the original bytes are what was sealed", ringBytes, sealer.received.single())
        assertEquals(active, EnrollmentSession.withKeyring { it.activeFingerprint })
        assertTrue("no acknowledgement of any kind", transport.reported.isEmpty() && transport.durableReports == 0)
    }

    @Test
    fun anInvalidRingTouchesNothing() = runBlocking {
        val previous = opener(OpenOutcome.NotEnrolled)

        assertEquals(KeyringImportOutcome.InvalidRing, import(expected = "A".repeat(40), opener = previous))
        assertEquals(KeyringImportOutcome.InvalidRing, import(bytes = "{}".toByteArray(), opener = previous))

        assertEquals("the vault was not even opened", 0, previous.opened)
        assertTrue(sealer.received.isEmpty())
        assertFalse(EnrollmentSession.isHeld())
        assertTrue(events.isEmpty())
    }

    @Test
    fun aFailedOrCancelledSealInstallsNothingAndCompletesNothing() = runBlocking {
        for (failure in listOf(SealOutcome.Failed("disk full"), SealOutcome.Cancelled, SealOutcome.NoSecureLockScreen)) {
            sealer.outcome = failure
            val outcome = import(opener = opener(OpenOutcome.NotEnrolled))
            assertEquals(failure.toString(), failure::class.simpleName, outcome::class.simpleName)
            assertFalse("no partial session install", EnrollmentSession.isHeld())
            assertTrue(events.isEmpty())
        }
        assertEquals(3, sealer.received.size)
    }

    @Test
    fun aPreviousVaultThatWillNotOpenIsNeverReplaced() = runBlocking {
        for (blocked in listOf(OpenOutcome.Cancelled, OpenOutcome.Failed("key invalidated"), OpenOutcome.NoSecureLockScreen)) {
            val outcome = import(opener = opener(blocked))
            assertEquals(blocked.toString(), blocked::class.simpleName, outcome::class.simpleName)
        }
        assertTrue("nothing sealed over an unopened record", sealer.received.isEmpty())
        assertFalse(EnrollmentSession.isHeld())
        assertTrue(events.isEmpty())
    }

    @Test
    fun theExactSameBytesReplayWithoutResealing() = runBlocking {
        EnrollmentSession.putKeyring(requireNotNull(parsePgpKeyring(ringBytes, active)))

        val outcome = import(opener = opener(OpenOutcome.Opened))

        assertEquals(KeyringImportOutcome.Replayed, outcome)
        assertTrue(sealer.received.isEmpty())
        assertEquals(listOf("complete"), events)
        assertNotNull(EnrollmentSession.withKeyring { it })
    }

    @Test
    fun aDifferentRingIsRefusedAndThePreviousOneKept() = runBlocking {
        EnrollmentSession.putKeyring(requireNotNull(parsePgpKeyring(ringBytes, active)))

        val outcome = import(bytes = laterRingBytes, opener = opener(OpenOutcome.Opened))

        assertEquals(KeyringImportOutcome.RefusedIncomparable, outcome)
        assertTrue(sealer.received.isEmpty())
        assertTrue(events.isEmpty())
        assertEquals(2L, EnrollmentSession.withKeyring { it.materialGeneration })
    }

    @Test
    fun legacyArmorIsIncomparableAndKept() = runBlocking {
        val outcome = import(opener = opener(OpenOutcome.Opened, TestPgpPrivateKey.ARMORED_PRIVATE))

        assertEquals(KeyringImportOutcome.RefusedIncomparable, outcome)
        assertTrue(sealer.received.isEmpty())
        assertTrue(events.isEmpty())
        assertEquals(TestPgpPrivateKey.ARMORED_PRIVATE, EnrollmentSession.peekForTest())
        assertNull(EnrollmentSession.withKeyring { it })
    }
}
