package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.data.ContactEntity

/** Both feed [signatureStateFor]'s local branch, the only source of VERIFIED_CONFIRMED. */
class LocalSignerKeyMappingTest {

    private fun contact(
        emails: String = """[{"value":"bob@example.com"}]""",
        pgpKey: String? = TestPgpKey.ARMORED,
        fingerprint: String? = "AAAA BBBB CCCC DDDD",
        needsReverification: Boolean = false,
        identityNeedsReview: Boolean = false,
    ) = ContactEntity(
        uid = "1",
        rev = 1,
        fn = "Bob",
        emailsJson = emails,
        pgpKey = pgpKey,
        pgpKeyFingerprint = fingerprint,
        pgpKeyNeedsReverification = needsReverification,
        identityNeedsReview = identityNeedsReview,
    )

    @Test
    fun anExactAddressMatches() {
        assertTrue(contact().hasEmail("bob@example.com"))
    }

    @Test
    fun matchingIsCaseInsensitiveAndIgnoresSurroundingSpace() {
        assertTrue(contact().hasEmail("BOB@Example.COM"))
        assertTrue(contact(emails = """[{"value":" bob@example.com "}]""").hasEmail("bob@example.com"))
    }

    @Test
    fun aSubstringIsNotAMatch() {
        // ContactDao.search does a LIKE over the raw emailsJson, which is right for autocomplete
        // and wrong for a trust decision: `bob@example.com` is a substring of
        // `notbob@example.com.evil.tld`, so the SQL narrows and this decides.
        assertFalse(contact(emails = """[{"value":"notbob@example.com.evil.tld"}]""").hasEmail("bob@example.com"))
    }

    @Test
    fun aSecondaryAddressStillMatches() {
        val twoAddresses = """[{"value":"other@example.com"},{"value":"bob@example.com"}]"""
        assertTrue(contact(emails = twoAddresses).hasEmail("bob@example.com"))
    }

    @Test
    fun anUndecodableEmailsColumnMatchesNothing() {
        assertFalse(contact(emails = "{not json").hasEmail("bob@example.com"))
    }

    @Test
    fun aRowWithNoKeyOffersNothing() {
        assertNull(contact(pgpKey = null).toLocalSignerKey())
        assertNull(contact(pgpKey = "   ").toLocalSignerKey())
    }

    @Test
    fun aRowWhoseKeyTheLocalParserRefusedOffersNothing() {
        // PgpFingerprint.compute returns null for an appended second key ring or an unbound subkey,
        // and its KDoc requires callers to treat that as "reject this key". A null fingerprint is
        // that rejection, recorded — so the row must not become a trust input at all.
        assertNull(contact(fingerprint = null).toLocalSignerKey())
    }

    @Test
    fun aCleanRowIsConfirmed() {
        assertEquals(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true), contact().toLocalSignerKey())
    }

    @Test
    fun anOutstandingKeyAlarmOffersTheKeyButNotConfirmation() {
        // Still offered, deliberately: signatureStateFor treats a locally-held key as authoritative
        // about WHICH key the sender uses regardless of confirmation, and that is what makes a
        // signature by some other key report KEY_CHANGED instead of falling through to the relay.
        val mapped = contact(needsReverification = true).toLocalSignerKey()
        assertEquals(LocalSignerKey(TestPgpKey.ARMORED, confirmed = false), mapped)
    }

    @Test
    fun anOutstandingIdentityAlarmAlsoBlocksConfirmation() {
        // The QR ceremony deliberately cannot clear this one — a fingerprint comparison attests to
        // the key and says nothing about which addresses it is displayed beside — so it has to gate
        // the badge that ceremony grants.
        val mapped = contact(identityNeedsReview = true).toLocalSignerKey()
        assertEquals(LocalSignerKey(TestPgpKey.ARMORED, confirmed = false), mapped)
    }

    /** The pin-only record keeps the same key, under each address, lowercased. */
    @Test
    fun recipientPins_carryTheRecordedKeyPerAddress() {
        val pins = contact(emails = """[{"value":"Bob@Example.com"},{"value":"bob@work.example"}]""").recipientPins()

        assertEquals(listOf("bob@example.com", "bob@work.example"), pins.map { it.address })
        assertTrue(pins.all { it.publicKey == TestPgpKey.ARMORED && it.fingerprint == "AAAA BBBB CCCC DDDD" && it.confirmed })
    }

    @Test
    fun recipientPins_noneWithoutARecordedKey() {
        assertTrue(contact(pgpKey = null).recipientPins().isEmpty())
    }
}
