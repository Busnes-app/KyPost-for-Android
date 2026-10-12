package org.kysecurity.mail.data

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The migration seeds pins from exactly what the earlier contact-key lookup trusted. */
class LegacyPinsTest {

    private val key = org.kysecurity.mail.pgp.TestPgpKey.ARMORED
    private val fingerprint = org.kysecurity.mail.pgp.PgpFingerprint.compute(key)!!

    @Test
    fun everyAddressOfAKeyedContactIsPinned_withItsConfirmation() {
        val pins = legacyPins(
            emailsJson = """[{"value":" Bob@Example.com "},{"label":"work","value":"bob@work.example"},{"value":""}]""",
            publicKey = key,
            fingerprint = fingerprint,
            confirmed = true,
        )

        assertEquals(
            listOf(
                RecipientPinEntity("bob@example.com", fingerprint, key, confirmed = true),
                RecipientPinEntity("bob@work.example", fingerprint, key, confirmed = true),
            ),
            pins,
        )
    }

    /** A row whose key was rejected kept the previous fingerprint: the pin is keyed on the bytes'
     *  own fingerprint, or none, and never carries the row's confirmation. */
    @Test
    fun aKeyThatIsNotTheOneItsFingerprintNames_isPinnedUnconfirmed() {
        val emails = """[{"value":"bob@example.com"}]"""

        assertEquals(
            listOf(RecipientPinEntity("bob@example.com", fingerprint, key, confirmed = false)),
            legacyPins(emails, publicKey = key, fingerprint = "OTHER", confirmed = true),
        )
        assertEquals(
            listOf(RecipientPinEntity("bob@example.com", "", "KEY", confirmed = false)),
            legacyPins(emails, publicKey = "KEY", fingerprint = "FP", confirmed = true),
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
