package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.kysecurity.mail.data.PendingContactSummary
import org.junit.Test

class ContactSyncStatusTest {

    private val now = 10_000_000L
    private val fresh = now - 60_000L
    private val old = now - STUCK_OUTBOX_AGE_MS - 1

    @Test
    fun nothingPendingAndNoFailures_isIdle() {
        assertEquals(ContactSyncStatus.Idle, contactSyncStatusOf(PendingContactSummary(0, null), ContactSyncFailures(), now))
    }

    @Test
    fun freshPendingChanges_areWaiting() {
        assertEquals(
            ContactSyncStatus.Waiting(2),
            contactSyncStatusOf(PendingContactSummary(2, fresh), ContactSyncFailures(), now),
        )
    }

    @Test
    fun oneFailureWithFreshChanges_isStillWaiting() {
        val failures = ContactSyncFailures(1, ContactSyncOutcome.Retry("network error"))
        assertEquals(
            ContactSyncStatus.Waiting(1),
            contactSyncStatusOf(PendingContactSummary(1, fresh), failures, now),
        )
    }

    @Test
    fun aChangeOlderThanTheThreshold_isStuck() {
        val failure = ContactSyncOutcome.Retry("network error")
        assertEquals(
            ContactSyncStatus.Stuck(1, failure),
            contactSyncStatusOf(PendingContactSummary(1, old), ContactSyncFailures(1, failure), now),
        )
    }

    @Test
    fun anOldChangeWithNoRecordedFailure_isStuckWithoutAReason() {
        assertEquals(
            ContactSyncStatus.Stuck(1, null),
            contactSyncStatusOf(PendingContactSummary(1, old), ContactSyncFailures(), now),
        )
    }

    @Test
    fun repeatedFailures_areStuckEvenWithAnEmptyOutbox() {
        val failure = ContactSyncOutcome.Unauthorized
        assertEquals(
            ContactSyncStatus.Stuck(0, failure),
            contactSyncStatusOf(PendingContactSummary(0, null), ContactSyncFailures(STUCK_AFTER_FAILURES, failure), now),
        )
    }

    @Test
    fun health_countsConsecutiveFailuresAndKeepsTheLatest() {
        val health = ContactSyncHealth()
        health.record(ContactSyncOutcome.Retry("a"))
        health.record(ContactSyncOutcome.ServiceUnavailable("b"))

        assertEquals(ContactSyncFailures(2, ContactSyncOutcome.ServiceUnavailable("b")), health.failures.value)
    }

    @Test
    fun health_successClearsTheFailures() {
        val health = ContactSyncHealth()
        health.record(ContactSyncOutcome.Retry("a"))
        health.record(ContactSyncOutcome.Success)

        assertEquals(ContactSyncFailures(), health.failures.value)
    }

    @Test
    fun health_notPairedIsNotASyncFailure() {
        val health = ContactSyncHealth()
        health.record(ContactSyncOutcome.Retry("a"))
        health.record(ContactSyncOutcome.NotPaired)

        assertEquals(ContactSyncFailures(1, ContactSyncOutcome.Retry("a")), health.failures.value)
    }
}
