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

    /** Not loaded yet: Save draft loads the list before it asks again. */
    @Test
    fun unknownAddressesRefuse() {
        assertFalse(plainDraftKeepsFrom("me@example.invalid", null))
    }

    /** A relay without native mailboxes has no other address: the draft's own From is the default. */
    @Test
    fun noAddresses_keepTheFrom() {
        assertTrue(plainDraftKeepsFrom("me@example.invalid", emptyList()))
    }

    /** With no address to pick, the account default is the only From, so nothing waits for a pick. */
    @Test
    fun aRequiredFrom_waitsForAPick_onlyWhileThereIsOneToMake() {
        assertTrue(fromPickPending(required = true, from = "", own = own))
        assertTrue("unknown: the picker loads and can retry", fromPickPending(required = true, from = "", own = null))
        assertFalse(fromPickPending(required = true, from = "", own = emptyList()))
        assertFalse(fromPickPending(required = true, from = "me@example.invalid", own = own))
        assertFalse(fromPickPending(required = false, from = "", own = own))
    }
}
