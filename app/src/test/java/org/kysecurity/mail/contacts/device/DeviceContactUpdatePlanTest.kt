package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactFieldDto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceContactUpdatePlanTest {

    private fun snapshot(
        fn: String = "Ada Lovelace",
        org: String? = null,
        notes: String? = null,
        birthday: String? = null,
        emails: List<ContactFieldDto> = emptyList(),
        phones: List<ContactFieldDto> = emptyList(),
        addresses: List<ContactAddressDto> = emptyList(),
    ) = DeviceRawContactSnapshot(
        rawContactId = 7,
        contactId = 3,
        accountType = DeviceContactAccount.ACCOUNT_TYPE,
        accountName = null,
        lastUpdatedEpochMs = 1_000,
        dirty = false,
        fn = fn,
        org = org,
        notes = notes,
        birthday = birthday,
        emails = emails,
        phones = phones,
        addresses = addresses,
    )

    private val roomNewer = 2_000L
    private val deviceOlder = 1_000L

    @Test
    fun identicalSides_planIsEmpty() {
        val emails = listOf(ContactFieldDto(label = "Home", value = "ada@example.com"))
        val plan = DeviceContactUpdatePlan.of(
            dto = ContactDto(uid = "u1", fn = "Ada Lovelace", emails = emails),
            snapshot = snapshot(emails = emails),
            roomUpdatedAtEpochMs = roomNewer,
            deviceUpdatedAtEpochMs = deviceOlder,
        )
        assertTrue(plan.isEmpty())
    }

    @Test
    fun roomWins_everyGroupIsPlanned_notJustTheName() {
        val plan = DeviceContactUpdatePlan.of(
            dto = ContactDto(
                uid = "u1",
                fn = "Ada Byron",
                org = "Analytical Engines",
                notes = "met at the fair",
                birthday = "1815-12-10",
                emails = listOf(ContactFieldDto(label = "Work", value = "ada@work.example")),
                phones = listOf(ContactFieldDto(label = "Mobile", value = "+15550001")),
                addresses = listOf(ContactAddressDto(label = "Home", city = "London")),
            ),
            snapshot = snapshot(
                fn = "Ada Lovelace",
                org = "Old Co",
                notes = "stale",
                birthday = "1815-12-11",
                emails = listOf(ContactFieldDto(label = "Home", value = "ada@old.example")),
                phones = listOf(ContactFieldDto(label = "Home", value = "+15559999")),
                addresses = listOf(ContactAddressDto(label = "Work", city = "Bath")),
            ),
            roomUpdatedAtEpochMs = roomNewer,
            deviceUpdatedAtEpochMs = deviceOlder,
        )

        assertFalse(plan.isEmpty())
        assertEquals("Ada Byron", plan.displayName)
        assertEquals("Analytical Engines", plan.org)
        assertEquals("met at the fair", plan.notes)
        assertEquals("1815-12-10", plan.birthday)
        assertEquals(listOf(ContactFieldDto(label = "Work", value = "ada@work.example")), plan.emails)
        assertEquals(listOf(ContactFieldDto(label = "Mobile", value = "+15550001")), plan.phones)
        assertEquals(listOf(ContactAddressDto(label = "Home", city = "London")), plan.addresses)
    }

    @Test
    fun deviceWins_nothingIsWrittenBack() {
        val plan = DeviceContactUpdatePlan.of(
            dto = ContactDto(
                uid = "u1",
                fn = "Ada Byron",
                org = "Analytical Engines",
                emails = listOf(ContactFieldDto(label = "Work", value = "ada@work.example")),
            ),
            snapshot = snapshot(
                fn = "Ada Lovelace",
                org = "Old Co",
                emails = listOf(ContactFieldDto(label = "Home", value = "ada@old.example")),
            ),
            roomUpdatedAtEpochMs = 1_000,
            deviceUpdatedAtEpochMs = 2_000,
        )
        assertTrue(plan.isEmpty())
    }

    @Test
    fun groupOnlyInRoom_isPlannedEvenThoughTheDeviceRowIsAbsent() {
        val plan = DeviceContactUpdatePlan.of(
            dto = ContactDto(
                uid = "u1",
                fn = "Ada Lovelace",
                org = "Analytical Engines",
                phones = listOf(ContactFieldDto(label = "Mobile", value = "+15550001")),
            ),
            // Device has neither an Organization nor a Phone row: an UPDATE would match nothing.
            snapshot = snapshot(),
            roomUpdatedAtEpochMs = deviceOlder,
            deviceUpdatedAtEpochMs = roomNewer,
        )
        assertEquals("Analytical Engines", plan.org)
        assertEquals(listOf(ContactFieldDto(label = "Mobile", value = "+15550001")), plan.phones)
        assertNull(plan.displayName)
    }

    @Test
    fun groupOnlyOnDevice_isNeverPlannedAsAnEmptyList() {
        val plan = DeviceContactUpdatePlan.of(
            dto = ContactDto(uid = "u1", fn = "Ada Lovelace"),
            snapshot = snapshot(
                emails = listOf(ContactFieldDto(label = "Home", value = "ada@old.example")),
                addresses = listOf(ContactAddressDto(label = "Home", city = "London")),
            ),
            roomUpdatedAtEpochMs = roomNewer,
            deviceUpdatedAtEpochMs = deviceOlder,
        )
        // Clearing them would delete rows Room simply has no opinion about.
        assertNull(plan.emails)
        assertNull(plan.addresses)
        assertTrue(plan.isEmpty())
    }

    /** Every field createRawContactForDto writes must also be updatable, or an edit to it never
     *  reaches a phone that already has the contact. */
    @Test
    fun roomEditsToEveryMappedField_arePlanned() {
        val dto = ContactDto(
            uid = "u1",
            fn = "Ada Lovelace",
            givenName = "Ada",
            familyName = "Lovelace",
            prefix = "Countess",
            phoneticGivenName = "AY-da",
            title = "Analyst",
            department = "Engines",
            ims = listOf(org.kysecurity.mail.contacts.ContactImDto(service = "matrix", value = "@ada:example.org")),
            websites = listOf(org.kysecurity.mail.contacts.ContactUrlDto(label = "blog", value = "https://ada.example")),
            relations = listOf(org.kysecurity.mail.contacts.ContactRelationDto(label = "Mentor", name = "Babbage")),
            events = listOf(org.kysecurity.mail.contacts.ContactEventDto(label = "anniversary", date = "1835-07-08")),
        )

        val plan = DeviceContactUpdatePlan.of(dto, snapshot(), roomNewer, deviceOlder)

        assertEquals("Ada", plan.givenName)
        assertEquals("Lovelace", plan.familyName)
        assertEquals("Countess", plan.prefix)
        assertEquals("AY-da", plan.phoneticGivenName)
        assertEquals("Analyst", plan.title)
        assertEquals("Engines", plan.department)
        assertEquals(dto.ims, plan.ims)
        assertEquals(dto.websites, plan.websites)
        assertEquals(dto.relations, plan.relations)
        assertEquals(dto.events, plan.events)
        assertTrue(plan.hasNameChange())
        assertTrue(plan.hasOrganizationChange())
    }

    /** Notes and an email removed on the server must leave the phone, not be re-uploaded from it. */
    @Test
    fun withABase_fieldsClearedInRoom_planAClear() {
        val email = listOf(ContactFieldDto(value = "ada@example.com"))
        val base = ContactDto(uid = "u1", fn = "Ada Lovelace", notes = "Old", emails = email)

        val plan = DeviceContactUpdatePlan.of(
            dto = base.copy(notes = null, emails = emptyList()),
            snapshot = snapshot(notes = "Old", emails = email),
            roomUpdatedAtEpochMs = roomNewer,
            deviceUpdatedAtEpochMs = deviceOlder,
            base = base,
        )

        assertEquals("", plan.notes)
        assertEquals(emptyList(), plan.emails)
        assertNull(plan.displayName)
    }

    /** A clear that the plan writes leaves both sides equal, so the base may advance. */
    @Test
    fun leavesDeviceMatching_afterAPlannedClear() {
        val base = ContactDto(uid = "u1", fn = "Ada Lovelace", notes = "Old")
        val dto = base.copy(notes = null)
        val device = snapshot(notes = "Old")

        val plan = DeviceContactUpdatePlan.of(dto, device, roomNewer, deviceOlder, base = base)

        assertTrue(plan.leavesDeviceMatching(dto, device))
    }

    /** An empty plan is not agreement: here the merge keeps the phone's note, which Room lacks,
     *  and advancing the base would make that note look like the phone's own new edit. */
    @Test
    fun anEmptyPlan_thatKeepsADeviceValue_isNotAgreement() {
        val dto = ContactDto(uid = "u1", fn = "Ada Lovelace", notes = null)
        val device = snapshot(notes = "Old")

        val plan = DeviceContactUpdatePlan.of(dto, device, roomNewer, deviceOlder, base = dto)

        assertTrue(plan.isEmpty())
        assertFalse(plan.leavesDeviceMatching(dto, device))
    }
}
