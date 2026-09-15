package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** A prepared keyring is enrolled for this device's own use and nothing else: the relay's
 *  boolean means "opens a v2 envelope", and no server field for a keyring exists yet. */
class EnrollmentStatusTest {

    @Test
    fun aKeyringRecordIsEnrolledLocally() {
        assertTrue(EnrollmentStatus.ENROLLED.isEnrolled())
        assertTrue(EnrollmentStatus.ENROLLED_KEYRING.isEnrolled())
        for (other in listOf(EnrollmentStatus.NO_KEY, EnrollmentStatus.KEY_INVALIDATED, EnrollmentStatus.NO_BLOB)) {
            assertFalse(other.name, other.isEnrolled())
        }
    }

    @Test
    fun onlyLegacyEnrollmentReachesTheLegacyReport() {
        assertTrue(EnrollmentStatus.ENROLLED.legacyReportValue())
        assertFalse("a prepared keyring must not be acknowledged as v2 enrollment", EnrollmentStatus.ENROLLED_KEYRING.legacyReportValue())
        for (other in listOf(EnrollmentStatus.NO_KEY, EnrollmentStatus.KEY_INVALIDATED, EnrollmentStatus.NO_BLOB)) {
            assertFalse(other.name, other.legacyReportValue())
        }
    }

    @Test
    fun theSettingsRowTreatsAKeyringAsEnrolled() {
        assertEquals(
            EnrollmentRow.Enrolled,
            enrollmentRowFor(
                paired = true, hostileLocation = false, hasSecureLockScreen = true,
                status = EnrollmentStatus.ENROLLED_KEYRING, identity = IdentityCheck.CouldNotCheck,
            ),
        )
    }
}
