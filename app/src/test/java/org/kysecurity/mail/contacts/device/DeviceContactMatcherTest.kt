package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactFieldDto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DeviceContactMatcherTest {
    @Test
    fun normalizeEmailTrimsAndLowercases() {
        assertEquals("test@example.com", DeviceContactMatcher.normalizeEmail("  TEST@EXAMPLE.COM  "))
    }

    @Test
    fun normalizePhoneStripsNonDigits() {
        assertEquals("5551234567", DeviceContactMatcher.normalizePhone("+1 (555) 123-4567"))
        assertEquals("5551234567", DeviceContactMatcher.normalizePhone("555.123.4567"))
    }

    @Test
    fun findMatchByEmail() {
        val existing = listOf(
            ContactDto(uid = "uid1", fn = "Alice", emails = listOf(ContactFieldDto(value = "alice@example.com"))),
        )
        val candidate = listOf("alice@EXAMPLE.COM")

        assertEquals("uid1", DeviceContactMatcher.findMatch(candidate, emptyList(), existing))
    }

    @Test
    fun findMatchByPhone() {
        val existing = listOf(
            ContactDto(uid = "uid2", fn = "Bob", phones = listOf(ContactFieldDto(value = "+1-555-987-6543"))),
        )
        val candidate = listOf("555-987-6543")

        assertEquals("uid2", DeviceContactMatcher.findMatch(emptyList(), candidate, existing))
    }

    @Test
    fun findMatchNoMatch() {
        val existing = listOf(
            ContactDto(uid = "uid3", fn = "Charlie", emails = listOf(ContactFieldDto(value = "charlie@example.com"))),
        )
        val candidate = listOf("notfound@example.com")

        assertNull(DeviceContactMatcher.findMatch(candidate, emptyList(), existing))
    }

    @Test
    fun findMatchEmptyExisting() {
        val existing = emptyList<ContactDto>()
        val candidate = listOf("test@example.com")

        assertNull(DeviceContactMatcher.findMatch(candidate, emptyList(), existing))
    }

    @Test
    fun findMatchEmptyCandidate() {
        val existing = listOf(
            ContactDto(uid = "uid4", fn = "David", emails = listOf(ContactFieldDto(value = "david@example.com"))),
        )

        assertNull(DeviceContactMatcher.findMatch(emptyList(), emptyList(), existing))
    }

    @Test
    fun findMatchOnANonFirstEmailOrPhone() {
        val existing = listOf(
            ContactDto(
                uid = "uid5",
                fn = "Eve",
                emails = listOf(
                    ContactFieldDto(value = "eve@work.example.com"),
                    ContactFieldDto(value = "eve@home.example.com"),
                ),
                phones = listOf(
                    ContactFieldDto(value = "555-000-0000"),
                    ContactFieldDto(value = "555-111-1111"),
                ),
            ),
        )

        assertEquals("uid5", DeviceContactMatcher.findMatch(listOf("eve@home.example.com"), emptyList(), existing))
        assertEquals("uid5", DeviceContactMatcher.findMatch(emptyList(), listOf("+1 555 111 1111"), existing))
    }

    @Test
    fun indexPrefersTheEarlierContactRegardlessOfWhichFieldMatched() {
        val existing = listOf(
            ContactDto(uid = "first", fn = "A", phones = listOf(ContactFieldDto(value = "555-222-2222"))),
            ContactDto(uid = "second", fn = "B", emails = listOf(ContactFieldDto(value = "b@example.com"))),
        )
        val index = DeviceContactMatcher.Index.of(existing)

        assertEquals("first", index.findMatch(listOf("b@example.com"), listOf("555-222-2222")))
    }

    @Test
    fun indexAgreesWithTheScanItReplaced() {
        val existing = (1..50).map { n ->
            ContactDto(
                uid = "uid$n",
                fn = "Contact $n",
                emails = listOf(ContactFieldDto(value = "person$n@example.com")),
                phones = listOf(ContactFieldDto(value = "555-000-${"%04d".format(n)}")),
            )
        }
        val index = DeviceContactMatcher.Index.of(existing)

        existing.forEach { contact ->
            val emails = contact.emails.map { it.value }
            val phones = contact.phones.map { it.value }
            assertEquals(
                DeviceContactMatcher.findMatch(emails, phones, existing),
                index.findMatch(emails, phones),
            )
        }
        assertNull(index.findMatch(listOf("nobody@example.com"), listOf("555-999-9999")))
    }

    /** A contact added mid-scan is found by the rest of the scan, behind every earlier owner. */
    @Test
    fun anAddedContactIsMatched_behindEarlierOwners() {
        val first = ContactDto(uid = "first", fn = "First", emails = listOf(ContactFieldDto(value = "shared@example.com")))
        val index = DeviceContactMatcher.Index.of(listOf(first))

        index.add(ContactDto(uid = "added", fn = "Added", phones = listOf(ContactFieldDto(value = "+1 555 123 4567")), emails = first.emails))

        assertEquals("added", index.findMatch(emptyList(), listOf("555-123-4567")))
        assertEquals("first", index.findMatch(listOf("SHARED@example.com"), listOf("555-123-4567")))
    }
}
