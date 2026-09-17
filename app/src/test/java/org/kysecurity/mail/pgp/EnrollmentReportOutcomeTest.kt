package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Test

/** The worker's retry decision as a pure function, so it can be asserted without a device. */
class EnrollmentReportOutcomeTest {

    /** The marker is now wrong in the unsafe direction — the Security page is telling the user this
     *  device can read their mail. Keep trying; offline is the expected case for the HLP path. */
    @Test
    fun aTransientFailureRetries() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network")),
        )
    }

    /** WorkManager applies no attempt ceiling of its own (work-runtime 2.10.1 only clamps backoff). */
    @Test
    fun retryingStopsAtTheAttemptCeiling() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network"), MAX_REPORT_ATTEMPTS - 1),
        )
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.Failed("no network"), MAX_REPORT_ATTEMPTS),
        )
    }

    /** The ceiling must not turn a success into a failure — it only bounds retrying. */
    @Test
    fun theCeilingDoesNotAffectSuccess() {
        assertEquals(
            EnrollmentReportOutcome.DONE,
            enrollmentReportOutcome(EnrollmentCallResult.Ok, MAX_REPORT_ATTEMPTS + 5),
        )
    }

    @Test
    fun rateLimitingRetries() {
        assertEquals(
            EnrollmentReportOutcome.RETRY,
            enrollmentReportOutcome(EnrollmentCallResult.RateLimited(42L)),
        )
    }

    /** A credential the server refuses will not start working on retry, and each attempt spends
     *  device-auth budget that the real device needs. */
    @Test
    fun aRefusedCredentialGivesUp() {
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.Unauthorized),
        )
    }

    @Test
    fun successIsDone() {
        assertEquals(EnrollmentReportOutcome.DONE, enrollmentReportOutcome(EnrollmentCallResult.Ok))
    }

    /** 409 means the server compared the claim with what it delivered and refused; the claim
     *  cannot become true by repeating it, and every attempt spends device-auth budget. */
    @Test
    fun aRefusedAcknowledgementGivesUp() {
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.Conflict),
        )
    }

    /** The teardown marker asks for a "not enrolled" that makes the server drop its delivery
     *  record. It is spent only when the correction landed or no device row remains to correct.
     *  An exhausted attempt budget is still transient: the worker is re-enqueued on every unlock
     *  and the same report stays truthful however long it waits. */
    @Test
    fun theTeardownMarkerIsSpentOnlyByALandedOrImpossibleReport() {
        assertEquals(true, teardownReportSpent(EnrollmentCallResult.Ok))
        assertEquals(true, teardownReportSpent(EnrollmentCallResult.Unauthorized))
        assertEquals(true, teardownReportSpent(EnrollmentCallResult.NotFound))
        assertEquals(false, teardownReportSpent(EnrollmentCallResult.Failed("offline")))
        assertEquals(false, teardownReportSpent(EnrollmentCallResult.RateLimited(42L)))
        // The same transient results at the ceiling are GIVE_UP for retry purposes, not spent.
        assertEquals(EnrollmentReportOutcome.GIVE_UP, enrollmentReportOutcome(EnrollmentCallResult.Failed("offline"), MAX_REPORT_ATTEMPTS))
        assertEquals(false, teardownReportSpent(EnrollmentCallResult.Failed("offline")))
    }

    /** 404 on this route means the device row is gone — deregistered, or the account deleted. */
    @Test
    fun aMissingDeviceRowIsDoneNotARetry() {
        assertEquals(
            EnrollmentReportOutcome.GIVE_UP,
            enrollmentReportOutcome(EnrollmentCallResult.NotFound),
        )
    }
}
