package org.kysecurity.mail.pgp

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** The agreement key and vault lifecycle; HPKE opening is `HpkeEnrollmentKeyStoreTest`. sealCipher
 *  is unreachable here: its key needs per-use auth from a BiometricPrompt. */
@RunWith(AndroidJUnit4::class)
class EnrollmentEnvelopeRoundTripTest {

    private val vault = EnrollmentVault(ApplicationProvider.getApplicationContext())

    @Before fun clean() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }
    @After fun cleanup() { EnrollmentKeyStore.deleteKeyPair(); vault.destroy() }

    /** The agreement key's life is one ceremony. A second `newKeyPair()` must not reuse the first. */
    @Test
    fun aFreshCeremonyRotatesTheAgreementKey() {
        assertTrue(EnrollmentKeyStore.newKeyPair())
        val first = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue(EnrollmentKeyStore.newKeyPair())
        val second = requireNotNull(EnrollmentKeyStore.rawPublicKey())

        assertTrue("a ceremony must not inherit the previous key", !first.contentEquals(second))
    }

    /** The vault half, end to end, minus the BiometricPrompt: seal with an authenticated cipher is
     *  not reachable here, but ensureKey/store/stored/destroy are. */
    @Test
    fun theVaultStoresAndDestroysWhatTheCeremonyWouldWrite() {
        assertTrue("no secure lock screen on this device — see the CI locksettings step", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 })

        assertNotNull(vault.stored())
        assertEquals(EnrollmentStatus.ENROLLED, probeEnrollment(vault))

        assertTrue(EnrollmentTeardown.destroy(ApplicationProvider.getApplicationContext()).isEmpty())

        // An instance held across teardown reports stale state; callers always build a fresh one.
        assertNull(EnrollmentVault(ApplicationProvider.getApplicationContext()).stored())
    }
}
