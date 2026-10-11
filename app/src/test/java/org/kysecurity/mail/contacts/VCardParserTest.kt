package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream

class VCardParserTest {

    private fun parse(text: String) = parseVCards(text.toByteArray(Charsets.UTF_8))

    private fun parsed(text: String): VCardImport.Parsed {
        val result = parse(text)
        assertTrue("expected Parsed, got $result", result is VCardImport.Parsed)
        return result as VCardImport.Parsed
    }

    private fun refused(text: String): VCardImport.Refusal = (parse(text) as VCardImport.Refused).reason

    private fun card(vararg lines: String, version: String = "4.0") =
        (listOf("BEGIN:VCARD", "VERSION:$version") + lines + "END:VCARD").joinToString("\r\n", postfix = "\r\n")

    private val jane = ContactDto(
        fn = "Jane O'Doe; Jr, \\ esq",
        givenName = "Jane",
        familyName = "O;Doe",
        middleName = "Q",
        prefix = "Dr",
        suffix = "Jr",
        nickname = "JJ",
        org = "Acme",
        department = "R&D",
        title = "Engineer",
        birthday = "1990-01-15",
        notes = "line one\nline two",
        emails = listOf(ContactFieldDto("Work", "jane@acme.example"), ContactFieldDto(null, "j@x.example")),
        phones = listOf(ContactFieldDto("Mobile", "+1 555 0100"), ContactFieldDto("Work Fax", "+1 555 0101")),
        addresses = listOf(ContactAddressDto("Home", "1 Main St", "Town", "ST", "12345", "US")),
        websites = listOf(ContactUrlDto(null, "https://jane.example")),
    )

    @Test
    fun roundTripsWhatTheWriterWrites_bothVersions() {
        VCardVersion.entries.forEach { version ->
            val result = parsed(writeVCards(listOf(jane, ContactDto(fn = "é".repeat(90))), version))
            assertEquals(version.name, listOf(jane, ContactDto(fn = "é".repeat(90))), result.contacts)
            assertEquals(0, result.skipped)
        }
    }

    @Test
    fun readsCommonV3Shapes() {
        val text = listOf(
            "BEGIN:VCARD",
            "VERSION:3.0",
            "N:Doe;John;;;",
            "item1.EMAIL;TYPE=INTERNET,HOME:john@home.example",
            "TEL;CELL:+1 555",
            "TEL;TYPE=WORK,VOICE:+1 666",
            "BDAY:1980-02-29T00:00:00Z",
            "NOTE:folded",
            "\tacross lines",
            "END:VCARD",
        ).joinToString("\n")
        val contact = parsed(text).contacts.single()
        assertEquals("John Doe", contact.fn)
        assertEquals(listOf(ContactFieldDto("Home", "john@home.example")), contact.emails)
        assertEquals(listOf(ContactFieldDto("Mobile", "+1 555"), ContactFieldDto("Work", "+1 666")), contact.phones)
        assertEquals("1980-02-29", contact.birthday)
        assertEquals("foldedacross lines", contact.notes)
    }

    @Test
    fun telUrisLoseTheirScheme() {
        assertEquals("+15550100", parsed(card("FN:A", "TEL;VALUE=uri:tel:+15550100")).contacts.single().phones.single().value)
    }

    @Test
    fun neverImportsUidKeysPhotosOrGroups() {
        val contact = parsed(
            card(
                "UID:urn:uuid:attacker-chosen",
                "FN:A",
                "KEY;MEDIATYPE=application/pgp-keys:data:application/pgp-keys;base64,AAAA",
                "PHOTO;ENCODING=b;TYPE=JPEG:AAAA",
                "CATEGORIES:friends",
                "X-KYPOST-ISSELF:true",
            ),
        ).contacts.single()
        assertEquals(ContactDto(fn = "A"), contact)
    }

    @Test
    fun encodedTextPropertiesAreSkippedNotMisread() {
        assertNull(parsed(card("FN:A", "NOTE;ENCODING=QUOTED-PRINTABLE:=41")).contacts.single().notes)
    }

    @Test
    fun aNamelessCardFallsBackToItsEmail_andAnEmptyOneIsSkipped() {
        val result = parsed(card("EMAIL:a@x.example") + card("NOTE:nothing else"))
        assertEquals(listOf("a@x.example"), result.contacts.map { it.fn })
        assertEquals(1, result.skipped)
    }

    @Test
    fun anInvalidBirthdayIsDropped() {
        assertNull(parsed(card("FN:A", "BDAY:19901345")).contacts.single().birthday)
    }

    @Test
    fun controlCharactersAreStripped() {
        assertEquals("AB", parsed(card("FN:A\u0007B")).contacts.single().fn)
        assertEquals("AB", parsed(card("FN:A\\\u0007B")).contacts.single().fn)
        assertEquals("A", parsed("\uFEFF" + card("FN:A\\")).contacts.single().fn)
    }

    @Test
    fun refusals() {
        assertEquals(VCardImport.Refusal.UNSUPPORTED_VERSION, refused(card("FN:A", version = "2.1")))
        assertEquals(VCardImport.Refusal.MALFORMED, refused("BEGIN:VCARD\r\nVERSION:4.0\r\nFN:A\r\n"))
        assertEquals(VCardImport.Refusal.MALFORMED, refused("BEGIN:VCARD\r\nVERSION:4.0\r\n" + card("FN:A") + "END:VCARD\r\n"))
        assertEquals(VCardImport.Refusal.MALFORMED, refused("hello\r\n" + card("FN:A")))
        assertEquals(VCardImport.Refusal.MALFORMED, refused(card("FN:A", "no colon here")))
        assertEquals(VCardImport.Refusal.MALFORMED, refused("BEGIN:VCARD\r\nFN:A\r\nEND:VCARD\r\n"))
        assertEquals(VCardImport.Refusal.EMPTY, refused(""))
        assertEquals(VCardImport.Refusal.EMPTY, refused(card("NOTE:x")))
    }

    @Test
    fun anyOtherBeginOrEndIsAStructuralError() {
        assertEquals(VCardImport.Refusal.MALFORMED, refused(card("FN:A") + card("FN:B", "END:OTHER")))
        assertEquals(VCardImport.Refusal.MALFORMED, refused(card("FN:A", "BEGIN:VEVENT")))
        assertEquals(VCardImport.Refusal.MALFORMED, refused("BEGIN:VCALENDAR\r\n" + card("FN:A")))
    }

    @Test
    fun invalidUtf8IsRefused() {
        val bytes = card("FN:A").toByteArray(Charsets.UTF_8) + byteArrayOf(0xC3.toByte(), 0x28)
        assertEquals(VCardImport.Refused(VCardImport.Refusal.NOT_UTF8), parseVCards(bytes))
    }

    @Test
    fun moreContactsThanTheCapAreRefusedWhole() {
        assertEquals(MAX_VCARD_IMPORT_CONTACTS, parsed(card("FN:A").repeat(MAX_VCARD_IMPORT_CONTACTS)).contacts.size)
        assertEquals(VCardImport.Refusal.TOO_MANY_CONTACTS, refused(card("FN:A").repeat(MAX_VCARD_IMPORT_CONTACTS + 1)))
    }

    @Test
    fun moreValuesThanTheServerKeepsAreRefused() {
        val emails = (0..MAX_VCARD_VALUES_PER_FIELD).map { "EMAIL:e$it@x.example" }.toTypedArray()
        assertEquals(VCardImport.Refusal.TOO_MANY_VALUES, refused(card("FN:A", *emails)))
    }

    @Test
    fun theReaderStopsAtTheSizeCap() {
        val big = ByteArray(MAX_VCARD_IMPORT_BYTES.toInt() + 1) { 'A'.code.toByte() }
        assertEquals(VCardImport.Refused(VCardImport.Refusal.TOO_LARGE), readVCardImport(ByteArrayInputStream(big)))
        assertTrue(readVCardImport(ByteArrayInputStream(card("FN:A").toByteArray())) is VCardImport.Parsed)
    }
}
