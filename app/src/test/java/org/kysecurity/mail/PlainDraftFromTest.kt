package org.kysecurity.mail

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** `/api/mail/draft` stores no From, so a saved plaintext draft reopens as the primary address. */
class PlainDraftFromTest {
    private val own = listOf("me@example.invalid", "x7k2@mask.example.invalid")

    @Test
    fun theDefaultOrThePrimaryIsKept() {
        assertTrue(plainDraftKeepsFrom("", null))
        assertTrue(plainDraftKeepsFrom("Me@Example.invalid", own))
    }

    @Test
    fun aMaskedOrTaggedFromIsRefused_notSavedAsThePrimary() {
        assertFalse(plainDraftKeepsFrom("x7k2@mask.example.invalid", own))
        assertFalse(plainDraftKeepsFrom("me+shop@example.invalid", own))
    }

    @Test
    fun unknownAddressesRefuse() {
        assertFalse(plainDraftKeepsFrom("me@example.invalid", null))
        assertFalse(plainDraftKeepsFrom("me@example.invalid", emptyList()))
    }
}
