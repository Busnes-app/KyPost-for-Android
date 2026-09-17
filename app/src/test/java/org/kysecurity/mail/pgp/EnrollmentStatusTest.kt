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

    /** The worker's report is derived from the probe plus the stored acknowledgement. A keyring
     *  record is never restated as the bare boolean: on a converted account that is refused, and
     *  on any account it would claim v2 enrollment that does not exist. */
    @Test
    fun theReportFollowsTheRecordKind() {
        val ack = EnrollmentReport.Keyring(materialGeneration = 2L, fingerprint = "5F117951610CAF01500FA059CDE63F0EBEC934A2")
        assertEquals(EnrollmentReport.Legacy, enrollmentReportFor(EnrollmentStatus.ENROLLED, ack = null))
        assertEquals(ack, enrollmentReportFor(EnrollmentStatus.ENROLLED_KEYRING, ack))
        assertEquals(EnrollmentReport.NotEnrolled, enrollmentReportFor(EnrollmentStatus.KEY_INVALIDATED, ack))
    }

    /** `NotEnrolled` makes the server forget the delivery it recorded for this device, so it is
     *  sent only on a proven loss: the Keystore's own invalidation verdict, or a deliberate
     *  teardown. A probe that merely threw (`NO_KEY`) or found no record on an ordinary unlock
     *  (`NO_BLOB`, which is also what a device awaiting its first delivery looks like) says nothing. */
    @Test
    fun anUnprovenProbeReportsNothing() {
        assertEquals(null, enrollmentReportFor(EnrollmentStatus.NO_KEY, ack = null))
        assertEquals(null, enrollmentReportFor(EnrollmentStatus.NO_BLOB, ack = null))
        assertEquals(null, enrollmentReportFor(EnrollmentStatus.NO_KEY, ack = null, tornDown = true))
    }

    @Test
    fun aDeliberateTeardownReportsNotEnrolled() {
        assertEquals(EnrollmentReport.NotEnrolled, enrollmentReportFor(EnrollmentStatus.NO_BLOB, ack = null, tornDown = true))
    }

    /** A keyring record whose acknowledgement values are missing has nothing truthful to say:
     *  neither true (unprovable) nor false (which would wipe the server's delivery record). */
    @Test
    fun aKeyringWithoutStoredAcknowledgementReportsNothing() {
        assertEquals(null, enrollmentReportFor(EnrollmentStatus.ENROLLED_KEYRING, ack = null))
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
