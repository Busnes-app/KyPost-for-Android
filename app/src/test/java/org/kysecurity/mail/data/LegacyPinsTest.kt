package org.kysecurity.mail.data

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The migration seeds pins from exactly what the earlier contact-key lookup trusted. */
class LegacyPinsTest {

    @Test
    fun everyAddressOfAKeyedContactIsPinned_withItsConfirmation() {
        val pins = legacyPins(
            emailsJson = """[{"value":" Bob@Example.com "},{"label":"work","value":"bob@work.example"},{"value":""}]""",
            publicKey = "KEY",
            fingerprint = "FP",
            confirmed = false,
        )

        assertEquals(
            listOf(
                RecipientPinEntity("bob@example.com", "FP", "KEY", confirmed = false),
                RecipientPinEntity("bob@work.example", "FP", "KEY", confirmed = false),
            ),
            pins,
        )
    }

    /** The old lookup returned nothing for these, so they were never trusted and are not pinned. */
    @Test
    fun aContactWithoutKeyOrFingerprint_pinsNothing() {
        val emails = """[{"value":"bob@example.com"}]"""
        assertTrue(legacyPins(emails, publicKey = null, fingerprint = "FP", confirmed = true).isEmpty())
        assertTrue(legacyPins(emails, publicKey = "KEY", fingerprint = "", confirmed = true).isEmpty())
        assertTrue(legacyPins("not json", publicKey = "KEY", fingerprint = "FP", confirmed = true).isEmpty())
    }
}
