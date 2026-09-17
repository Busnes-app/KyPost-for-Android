package org.kysecurity.mail.pgp

import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** The port's contract, not the Keystore: an [OpenOutcome] never carries key material. */
class VaultOpenerContractTest {

    @After fun cleanup() = EnrollmentSession.clear()

    private class FakeOpener(private val outcome: OpenOutcome, private val key: String? = null) : VaultOpener {
        override fun sealedKind(): VaultRecordKind? = null
        override suspend fun open(): OpenOutcome {
            if (key != null) EnrollmentSession.put(key.toCharArray())
            return outcome
        }
    }

    @Test
    fun openingPutsTheKeyInTheSessionAndReturnsNoMaterial() {
        val opener = FakeOpener(OpenOutcome.Opened, "-----BEGIN PGP PRIVATE KEY BLOCK-----")

        val outcome = runBlocking { opener.open() }

        assertEquals(OpenOutcome.Opened, outcome)
        assertEquals("-----BEGIN PGP PRIVATE KEY BLOCK-----", EnrollmentSession.peekForTest())
    }

    @Test
    fun cancellingLeavesTheSessionEmpty() {
        val opener = FakeOpener(OpenOutcome.Cancelled)

        val outcome = runBlocking { opener.open() }

        assertEquals(OpenOutcome.Cancelled, outcome)
        assertNull(EnrollmentSession.peekForTest())
    }
}
