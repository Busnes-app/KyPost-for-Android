package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.extensionForMimeType

class VCardWriterTest {

    private val jane = ContactDto(
        uid = "server-uid",
        fn = "Jane Doe",
        givenName = "Jane",
        familyName = "Doe",
        org = "Acme",
        department = "R&D",
        title = "Engineer",
        birthday = "1990-01-15",
        notes = "line one\nline two",
        emails = listOf(ContactFieldDto("Work", "jane@acme.example")),
        phones = listOf(ContactFieldDto("Mobile", "+1 555 0100")),
        addresses = listOf(ContactAddressDto("Home", "1 Main St", "Town", "ST", "12345", "US")),
        websites = listOf(ContactUrlDto(null, "https://jane.example")),
    )

    @Test
    fun v4_writesTheMappedFields() {
        assertEquals(
            listOf(
                "BEGIN:VCARD",
                "VERSION:4.0",
                "FN:Jane Doe",
                "N:Doe;Jane;;;",
                "ORG:Acme;R&D",
                "TITLE:Engineer",
                "EMAIL;TYPE=work:jane@acme.example",
                "TEL;TYPE=cell:+1 555 0100",
                "ADR;TYPE=home:;;1 Main St;Town;ST;12345;US",
                "URL:https://jane.example",
                "BDAY:19900115",
                "NOTE:line one\\nline two",
                "END:VCARD",
                "",
            ).joinToString("\r\n"),
            writeVCards(listOf(jane), VCardVersion.V4),
        )
    }

    @Test
    fun v3_usesItsVersionAndDateForm() {
        val card = writeVCards(listOf(jane), VCardVersion.V3)
        assertTrue(card.contains("\r\nVERSION:3.0\r\n"))
        assertTrue(card.contains("\r\nBDAY:1990-01-15\r\n"))
    }

    @Test
    fun theServerUidIsNotExported() {
        assertFalse(writeVCards(listOf(jane), VCardVersion.V4).contains("server-uid"))
    }

    @Test
    fun textIsEscapedSoAValueCannotInjectAProperty() {
        val hostile = ContactDto(fn = "Eve\r\nEND:VCARD\r\nBEGIN:VCARD\r\nFN:Mallory; a, b\\c")
        val card = writeVCards(listOf(hostile), VCardVersion.V4)
        assertEquals(listOf("BEGIN:VCARD"), card.split("\r\n").filter { it.startsWith("BEGIN:") })
        assertTrue(card.contains("FN:Eve\\nEND:VCARD\\nBEGIN:VCARD\\nFN:Mallory\\; a\\, b\\\\c\r\n"))
    }

    @Test
    fun urlsAndTypeLabelsCannotBreakTheLineOrParameters() {
        val hostile = ContactDto(
            fn = "X",
            websites = listOf(ContactUrlDto(null, "https://a.example/\r\nNOTE:injected")),
            emails = listOf(ContactFieldDto("we\"ird:label;x", "x@example.org")),
        )
        val card = writeVCards(listOf(hostile), VCardVersion.V4)
        assertFalse(card.contains("\r\nNOTE:"))
        assertTrue(card.contains("EMAIL;TYPE=\"weird:label;x\":x@example.org\r\n"))
    }

    @Test
    fun longLinesFoldAt75OctetsWithoutSplittingACharacter() {
        val card = writeVCards(listOf(ContactDto(fn = "é".repeat(100))), VCardVersion.V4)
        val lines = card.split("\r\n")
        lines.forEach { assertTrue("line over 75 octets: $it", it.toByteArray(Charsets.UTF_8).size <= 75) }
        val unfolded = card.replace("\r\n ", "")
        assertTrue(unfolded.contains("FN:" + "é".repeat(100) + "\r\n"))
    }

    @Test
    fun aMalformedBirthdayIsLeftOut() {
        assertFalse(writeVCards(listOf(ContactDto(fn = "X", birthday = "soon")), VCardVersion.V4).contains("BDAY"))
    }

    @Test
    fun aBirthdayThatIsNotACalendarDateIsLeftOut_bothVersions() {
        VCardVersion.entries.forEach { version ->
            listOf("2025-02-29", "2026-13-01", "+10000-01-01").forEach { date ->
                assertFalse("$version $date", writeVCards(listOf(ContactDto(fn = "X", birthday = date)), version).contains("BDAY"))
            }
        }
        assertTrue(writeVCards(listOf(ContactDto(fn = "X", birthday = "2024-02-29")), VCardVersion.V4).contains("\r\nBDAY:20240229\r\n"))
        assertTrue(writeVCards(listOf(ContactDto(fn = "X", birthday = "2024-02-29")), VCardVersion.V3).contains("\r\nBDAY:2024-02-29\r\n"))
    }

    @Test
    fun aCommaInAFreeTextLabelIsQuoted_whileFaxStaysTwoTypes() {
        val card = writeVCards(
            listOf(
                ContactDto(
                    fn = "X",
                    emails = listOf(ContactFieldDto("home,work", "x@example.org")),
                    phones = listOf(ContactFieldDto("Work Fax", "+1"), ContactFieldDto("a,b", "+2")),
                ),
            ),
            VCardVersion.V4,
        )
        assertTrue(card.contains("\r\nEMAIL;TYPE=\"home,work\":x@example.org\r\n"))
        assertTrue(card.contains("\r\nTEL;TYPE=work,fax:+1\r\n"))
        assertTrue(card.contains("\r\nTEL;TYPE=\"a,b\":+2\r\n"))
    }

    @Test
    fun severalContactsAreConcatenated() {
        val card = writeVCards(listOf(ContactDto(fn = "A"), ContactDto(fn = "B")), VCardVersion.V3)
        assertEquals(2, Regex("BEGIN:VCARD").findAll(card).count())
    }

    @Test
    fun vcardMimeTypeGetsAVcfExtension() {
        assertEquals("vcf", extensionForMimeType(VCARD_MIME_TYPE))
    }
}
