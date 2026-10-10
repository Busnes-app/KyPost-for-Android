package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class SendReadinessTest {

    @Test
    fun aBlankSubjectAsksInsteadOfRefusing() {
        assertEquals(SendReadiness.CONFIRM_EMPTY_SUBJECT, sendReadiness("a@example.com", " ", false, false))
    }

    @Test
    fun aConfirmedBlankSubjectSends() {
        assertEquals(SendReadiness.READY, sendReadiness("a@example.com", "", false, true))
    }

    @Test
    fun recipientAndBodyAreStillRequired() {
        assertEquals(SendReadiness.INCOMPLETE, sendReadiness("", "Hi", false, true))
        assertEquals(SendReadiness.INCOMPLETE, sendReadiness("a@example.com", "Hi", true, true))
    }

    @Test
    fun aCompleteMessageSends() {
        assertEquals(SendReadiness.READY, sendReadiness("a@example.com", "Hi", false, false))
    }
}
