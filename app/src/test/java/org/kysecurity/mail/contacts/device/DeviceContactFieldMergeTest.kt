package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DeviceContactFieldMergeTest {
    @Test
    fun mergeStringBothEmpty() {
        assertNull(DeviceContactFieldMerge.mergeStringField(null, null, null, null))
        assertNull(DeviceContactFieldMerge.mergeStringField("", "", null, null))
    }

    @Test
    fun mergeStringRoomEmptyDevicePopulated() {
        assertEquals("device value", DeviceContactFieldMerge.mergeStringField(null, "device value", null, 100L))
        assertEquals("device value", DeviceContactFieldMerge.mergeStringField("", "device value", null, 100L))
    }

    @Test
    fun mergeStringRoomPopulatedDeviceEmpty() {
        assertEquals("room value", DeviceContactFieldMerge.mergeStringField("room value", null, 100L, null))
        assertEquals("room value", DeviceContactFieldMerge.mergeStringField("room value", "", 100L, null))
    }

    @Test
    fun mergeStringBothPopulatedRoomNewer() {
        assertEquals("room value", DeviceContactFieldMerge.mergeStringField("room value", "device value", 200L, 100L))
    }

    @Test
    fun mergeStringBothPopulatedDeviceNewer() {
        assertEquals("device value", DeviceContactFieldMerge.mergeStringField("room value", "device value", 100L, 200L))
    }

    @Test
    fun mergeStringBothPopulatedTieThenRoomWins() {
        assertEquals("room value", DeviceContactFieldMerge.mergeStringField("room value", "device value", 100L, 100L))
    }

    @Test
    fun mergeEmailListBothEmpty() {
        assertEquals(emptyList<org.kysecurity.mail.contacts.ContactFieldDto>(), DeviceContactFieldMerge.mergeEmailList(emptyList(), emptyList(), null, null))
    }

    @Test
    fun mergeEmailListRoomEmptyDevicePopulated() {
        val deviceEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "test@example.com"))
        assertEquals(deviceEmails, DeviceContactFieldMerge.mergeEmailList(emptyList(), deviceEmails, null, 100L))
    }

    @Test
    fun mergeEmailListRoomPopulatedDeviceEmpty() {
        val roomEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "test@example.com"))
        assertEquals(roomEmails, DeviceContactFieldMerge.mergeEmailList(roomEmails, emptyList(), 100L, null))
    }

    @Test
    fun mergeEmailListBothPopulatedRoomNewer() {
        val roomEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "room@example.com"))
        val deviceEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "device@example.com"))
        assertEquals(roomEmails, DeviceContactFieldMerge.mergeEmailList(roomEmails, deviceEmails, 200L, 100L))
    }

    @Test
    fun mergeEmailListBothPopulatedDeviceNewer() {
        val roomEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "room@example.com"))
        val deviceEmails = listOf(org.kysecurity.mail.contacts.ContactFieldDto(value = "device@example.com"))
        assertEquals(deviceEmails, DeviceContactFieldMerge.mergeEmailList(roomEmails, deviceEmails, 100L, 200L))
    }

    @Test
    fun mergeImListBothEmpty() {
        assertEquals(emptyList<ContactImDto>(), DeviceContactFieldMerge.mergeImList(emptyList(), emptyList(), null, null))
    }

    @Test
    fun mergeImListRoomEmptyDevicePopulated() {
        val deviceIms = listOf(ContactImDto(service = "signal", value = "+15551234567"))
        assertEquals(deviceIms, DeviceContactFieldMerge.mergeImList(emptyList(), deviceIms, null, 100L))
    }

    @Test
    fun mergeImListRoomPopulatedDeviceEmpty() {
        val roomIms = listOf(ContactImDto(service = "signal", value = "+15551234567"))
        assertEquals(roomIms, DeviceContactFieldMerge.mergeImList(roomIms, emptyList(), 100L, null))
    }

    @Test
    fun mergeImListBothPopulatedRoomNewer() {
        val roomIms = listOf(ContactImDto(service = "signal", value = "room"))
        val deviceIms = listOf(ContactImDto(service = "signal", value = "device"))
        assertEquals(roomIms, DeviceContactFieldMerge.mergeImList(roomIms, deviceIms, 200L, 100L))
    }

    @Test
    fun mergeImListBothPopulatedDeviceNewer() {
        val roomIms = listOf(ContactImDto(service = "signal", value = "room"))
        val deviceIms = listOf(ContactImDto(service = "signal", value = "device"))
        assertEquals(deviceIms, DeviceContactFieldMerge.mergeImList(roomIms, deviceIms, 100L, 200L))
    }

    @Test
    fun mergeWebsiteListBothEmpty() {
        assertEquals(emptyList<ContactUrlDto>(), DeviceContactFieldMerge.mergeWebsiteList(emptyList(), emptyList(), null, null))
    }

    @Test
    fun mergeWebsiteListRoomEmptyDevicePopulated() {
        val deviceWebsites = listOf(ContactUrlDto(value = "https://example.com"))
        assertEquals(deviceWebsites, DeviceContactFieldMerge.mergeWebsiteList(emptyList(), deviceWebsites, null, 100L))
    }

    @Test
    fun mergeWebsiteListRoomPopulatedDeviceEmpty() {
        val roomWebsites = listOf(ContactUrlDto(value = "https://example.com"))
        assertEquals(roomWebsites, DeviceContactFieldMerge.mergeWebsiteList(roomWebsites, emptyList(), 100L, null))
    }

    @Test
    fun mergeWebsiteListBothPopulatedRoomNewer() {
        val roomWebsites = listOf(ContactUrlDto(value = "https://room.example.com"))
        val deviceWebsites = listOf(ContactUrlDto(value = "https://device.example.com"))
        assertEquals(roomWebsites, DeviceContactFieldMerge.mergeWebsiteList(roomWebsites, deviceWebsites, 200L, 100L))
    }

    @Test
    fun mergeWebsiteListBothPopulatedDeviceNewer() {
        val roomWebsites = listOf(ContactUrlDto(value = "https://room.example.com"))
        val deviceWebsites = listOf(ContactUrlDto(value = "https://device.example.com"))
        assertEquals(deviceWebsites, DeviceContactFieldMerge.mergeWebsiteList(roomWebsites, deviceWebsites, 100L, 200L))
    }

    @Test
    fun mergeRelationListBothEmpty() {
        assertEquals(emptyList<ContactRelationDto>(), DeviceContactFieldMerge.mergeRelationList(emptyList(), emptyList(), null, null))
    }

    @Test
    fun mergeRelationListRoomEmptyDevicePopulated() {
        val deviceRelations = listOf(ContactRelationDto(label = "spouse", name = "Alex"))
        assertEquals(deviceRelations, DeviceContactFieldMerge.mergeRelationList(emptyList(), deviceRelations, null, 100L))
    }

    @Test
    fun mergeRelationListRoomPopulatedDeviceEmpty() {
        val roomRelations = listOf(ContactRelationDto(label = "spouse", name = "Alex"))
        assertEquals(roomRelations, DeviceContactFieldMerge.mergeRelationList(roomRelations, emptyList(), 100L, null))
    }

    @Test
    fun mergeRelationListBothPopulatedRoomNewer() {
        val roomRelations = listOf(ContactRelationDto(label = "spouse", name = "Room Person"))
        val deviceRelations = listOf(ContactRelationDto(label = "spouse", name = "Device Person"))
        assertEquals(roomRelations, DeviceContactFieldMerge.mergeRelationList(roomRelations, deviceRelations, 200L, 100L))
    }

    @Test
    fun mergeRelationListBothPopulatedDeviceNewer() {
        val roomRelations = listOf(ContactRelationDto(label = "spouse", name = "Room Person"))
        val deviceRelations = listOf(ContactRelationDto(label = "spouse", name = "Device Person"))
        assertEquals(deviceRelations, DeviceContactFieldMerge.mergeRelationList(roomRelations, deviceRelations, 100L, 200L))
    }

    @Test
    fun mergeEventListBothEmpty() {
        assertEquals(emptyList<ContactEventDto>(), DeviceContactFieldMerge.mergeEventList(emptyList(), emptyList(), null, null))
    }

    @Test
    fun mergeEventListRoomEmptyDevicePopulated() {
        val deviceEvents = listOf(ContactEventDto(label = "anniversary", date = "2020-06-01"))
        assertEquals(deviceEvents, DeviceContactFieldMerge.mergeEventList(emptyList(), deviceEvents, null, 100L))
    }

    @Test
    fun mergeEventListRoomPopulatedDeviceEmpty() {
        val roomEvents = listOf(ContactEventDto(label = "anniversary", date = "2020-06-01"))
        assertEquals(roomEvents, DeviceContactFieldMerge.mergeEventList(roomEvents, emptyList(), 100L, null))
    }

    @Test
    fun mergeEventListBothPopulatedRoomNewer() {
        val roomEvents = listOf(ContactEventDto(label = "anniversary", date = "2020-06-01"))
        val deviceEvents = listOf(ContactEventDto(label = "anniversary", date = "2021-06-01"))
        assertEquals(roomEvents, DeviceContactFieldMerge.mergeEventList(roomEvents, deviceEvents, 200L, 100L))
    }

    @Test
    fun mergeEventListBothPopulatedDeviceNewer() {
        val roomEvents = listOf(ContactEventDto(label = "anniversary", date = "2020-06-01"))
        val deviceEvents = listOf(ContactEventDto(label = "anniversary", date = "2021-06-01"))
        assertEquals(deviceEvents, DeviceContactFieldMerge.mergeEventList(roomEvents, deviceEvents, 100L, 200L))
    }

    private fun stringAgainstBase(room: String?, device: String?, base: String?, known: Boolean = true) =
        DeviceContactFieldMerge.againstBase(room, device, base, known) { r, d ->
            DeviceContactFieldMerge.mergeStringField(r, d, 200L, 100L)
        }

    @Test
    fun againstBase_aFieldClearedOnTheDevice_staysCleared() {
        assertNull(stringAgainstBase(room = "Old notes", device = null, base = "Old notes"))
    }

    @Test
    fun againstBase_aFieldClearedInRoom_staysCleared() {
        assertNull(stringAgainstBase(room = null, device = "Old notes", base = "Old notes"))
    }

    @Test
    fun againstBase_aListClearedOnTheDevice_staysCleared() {
        val emails = listOf(ContactFieldDto(value = "ada@example.com"))
        val merged = DeviceContactFieldMerge.againstBase(emails, emptyList(), emails, true) { r, d ->
            DeviceContactFieldMerge.mergeEmailList(r, d, 200L, 100L)
        }
        assertEquals(emptyList(), merged)
    }

    @Test
    fun againstBase_changedOnBothSides_fallsBackToTwoWay() {
        assertEquals("Room", stringAgainstBase(room = "Room", device = "Device", base = "Base"))
    }

    /** Rows linked before a base was kept: two-way cannot tell cleared from unset, so Room keeps it. */
    @Test
    fun againstBase_withoutABase_keepsTheTwoWayRule() {
        assertEquals("Old notes", stringAgainstBase(room = "Old notes", device = null, base = null, known = false))
    }
}
