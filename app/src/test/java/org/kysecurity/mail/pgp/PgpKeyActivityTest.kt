package org.kysecurity.mail.pgp

import org.kysecurity.mail.contacts.ContactFieldDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test

class PgpKeyActivityTest {

    private val fp = TestPgpKey.FINGERPRINT.replace(" ", "")

    @Test
    fun ownQrUrl_withFingerprint_carriesItCompactInTheFragment() {
        assertEquals(
            "https://mail.example.com/api/pgp/qr/key?t=abc123#fp=$fp",
            PgpKeyActivity.ownQrUrl("https://mail.example.com/", "abc123", TestPgpKey.FINGERPRINT),
        )
    }

    @Test
    fun ownQrUrl_withoutFingerprint_hasNoFragment() {
        assertEquals(
            "https://mail.example.com/api/pgp/qr/key?t=abc123",
            PgpKeyActivity.ownQrUrl("https://mail.example.com", "abc123", null),
        )
    }

    @Test
    fun ownQrUrl_nonV4Fingerprint_isLeftOut() {
        val url = PgpKeyActivity.ownQrUrl("https://mail.example.com", "abc123", "AB".repeat(32))
        assertFalse(url!!.contains('#'))
    }

    @Test
    fun ownQrUrl_roundTripsThroughTheParser() {
        val url = PgpKeyActivity.ownQrUrl("https://mail.example.com", "abc123", TestPgpKey.FINGERPRINT)!!
        assertEquals(
            ParsedPgpQrKeyUrl("https://mail.example.com", "abc123", fp),
            PgpKeyActivity.parsePgpQrKeyUrl(url),
        )
    }

    @Test
    fun parsePgpQrKeyUrl_otherFragment_isNotReadAsAbsent() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl("https://mail.example.com/api/pgp/qr/key?t=abc123#x=1")!!
        assertEquals(ScannedKeyCheck.MISMATCH, PgpKeyActivity.checkScannedKey(parsed.fingerprint, TestPgpKey.FINGERPRINT))
    }

    @Test
    fun scannedKey_matchingFingerprint_isConfirmed() {
        assertEquals(ScannedKeyCheck.CONFIRMED, PgpKeyActivity.checkScannedKey(fp, TestPgpKey.FINGERPRINT))
    }

    @Test
    fun scannedKey_differentFingerprint_isMismatch() {
        val other = TestPgpPrivateKey.FINGERPRINT.replace(" ", "")
        assertEquals(ScannedKeyCheck.MISMATCH, PgpKeyActivity.checkScannedKey(other, TestPgpKey.FINGERPRINT))
    }

    @Test
    fun scannedKey_malformedFingerprint_isMismatch() {
        listOf("", fp.dropLast(1), fp + "0", fp.lowercase(), fp.dropLast(1) + "G", TestPgpKey.FINGERPRINT).forEach {
            assertEquals(it, ScannedKeyCheck.MISMATCH, PgpKeyActivity.checkScannedKey(it, TestPgpKey.FINGERPRINT))
        }
    }

    @Test
    fun scannedKey_noFingerprint_isUnverified() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl("https://mail.example.com/api/pgp/qr/key?t=abc123")!!
        assertNull(parsed.fingerprint)
        assertEquals(ScannedKeyCheck.UNVERIFIED, PgpKeyActivity.checkScannedKey(parsed.fingerprint, TestPgpKey.FINGERPRINT))
    }

    @Test
    fun parsePgpQrKeyUrl_validUrl_extractsServerUrlAndToken() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key?t=abc123",
        )

        assertEquals(ParsedPgpQrKeyUrl(serverUrl = "https://mail.example.com", token = "abc123"), parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_malformedString_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl("not a url at all")

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_wrongPath_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/token?t=abc123",
        )

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_missingTParam_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key",
        )

        assertNull(parsed)
    }

    @Test
    fun parsePgpQrKeyUrl_blankTParam_returnsNull() {
        val parsed = PgpKeyActivity.parsePgpQrKeyUrl(
            "https://mail.example.com/api/pgp/qr/key?t=",
        )

        assertNull(parsed)
    }

    @Test
    fun contactDtoFromCard_mapsAllFields() {
        val card = PgpQrContactCardDto(
            fn = "Alice Example",
            givenName = "Alice",
            familyName = "Example",
            org = "Example Corp",
            title = "Engineer",
            emails = listOf(ContactFieldDto(label = "work", value = "alice@example.com")),
            phones = listOf(ContactFieldDto(value = "+1-555-0100")),
            notes = "Met at conference",
            pronouns = "she/her",
        )

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "Alice", pgpKey = "PUBKEY")

        assertEquals("Alice Example", dto.fn)
        assertEquals("Alice", dto.givenName)
        assertEquals("Example", dto.familyName)
        assertEquals("Example Corp", dto.org)
        assertEquals("Engineer", dto.title)
        assertEquals("alice@example.com", dto.emails.single().value)
        assertEquals("+1-555-0100", dto.phones.single().value)
        assertEquals("Met at conference", dto.notes)
        assertEquals("she/her", dto.pronouns)
        assertEquals("PUBKEY", dto.pgpKey)
    }

    @Test
    fun contactDtoFromCard_blankCardName_fallsBackToScannedName() {
        val card = PgpQrContactCardDto(fn = null)

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "Alice", pgpKey = "PUBKEY")

        assertEquals("Alice", dto.fn)
    }

    @Test
    fun contactDtoFromCard_blankCardNameAndBlankFallback_usesUnknown() {
        val card = PgpQrContactCardDto(fn = null)

        val dto = PgpKeyActivity.contactDtoFromCard(card, fallbackName = "", pgpKey = "PUBKEY")

        assertEquals("Unknown", dto.fn)
    }
}
