package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto

object DeviceContactFieldMerge {
    /** Three-way merge against [base], the value both sides held after the last sync. A side still
     *  equal to it did not change, so the other side wins, including a field it emptied. Without a
     *  base, or with a change on both sides, [twoWay] decides; it cannot tell cleared from unset. */
    fun <T> againstBase(room: T, device: T, base: T?, baseKnown: Boolean, twoWay: (T, T) -> T): T = when {
        !baseKnown -> twoWay(room, device)
        same(device, base) -> room
        same(room, base) -> device
        else -> twoWay(room, device)
    }

    /** Compares as CP2 stores: null, blank and empty are one value, since CP2 drops an empty row,
     *  and labels ignore case, since CP2 reads Room's "home" back as TYPE_HOME, "Home". */
    fun same(a: Any?, b: Any?): Boolean = a == b || normal(a) == normal(b)

    private fun normal(v: Any?): Any? = when (v) {
        is String -> v.trim().ifEmpty { null }
        is Collection<*> -> v.map(::normal).ifEmpty { null }
        is ContactFieldDto -> v.copy(label = label(v.label), value = v.value.trim())
        is ContactAddressDto -> ContactAddressDto(
            label = label(v.label),
            street = normal(v.street) as String?,
            city = normal(v.city) as String?,
            region = normal(v.region) as String?,
            postalCode = normal(v.postalCode) as String?,
            country = normal(v.country) as String?,
        )
        else -> v
    }

    private fun label(l: String?): String? = l?.trim()?.lowercase()?.ifEmpty { null }

    fun <T> mergeField(
        roomValue: T?,
        deviceValue: T?,
        isEmpty: (T) -> Boolean,
        recordWinner: (T?, Winner) -> Unit,
    ): T? {
        val roomEmpty = roomValue == null || isEmpty(roomValue)
        val deviceEmpty = deviceValue == null || isEmpty(deviceValue)

        return when {
            roomEmpty && deviceEmpty -> {
                recordWinner(null, Winner.TIE_PREFER_ROOM)
                null
            }
            roomEmpty && !deviceEmpty -> {
                recordWinner(deviceValue, Winner.DEVICE)
                deviceValue
            }
            !roomEmpty && deviceEmpty -> {
                recordWinner(roomValue, Winner.ROOM)
                roomValue
            }
            else -> {
                val winner = Winner.TIE_PREFER_ROOM
                val result = roomValue
                recordWinner(result ?: deviceValue, winner)
                result
            }
        }
    }

    fun mergeStringField(
        roomValue: String?,
        deviceValue: String?,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): String? {
        val roomEmpty = roomValue.isNullOrBlank()
        val deviceEmpty = deviceValue.isNullOrBlank()

        return when {
            roomEmpty && deviceEmpty -> null
            roomEmpty && !deviceEmpty -> deviceValue
            !roomEmpty && deviceEmpty -> roomValue
            else -> {
                val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
                when (winner) {
                    Winner.DEVICE -> deviceValue
                    else -> roomValue
                }
            }
        }
    }

    fun mergeEmailList(
        roomEmails: List<ContactFieldDto>,
        deviceEmails: List<ContactFieldDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactFieldDto> {
        if (roomEmails.isEmpty() && deviceEmails.isEmpty()) return emptyList()
        if (roomEmails.isEmpty()) return deviceEmails
        if (deviceEmails.isEmpty()) return roomEmails

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceEmails
            else -> roomEmails
        }
    }

    fun mergePhoneList(
        roomPhones: List<ContactFieldDto>,
        devicePhones: List<ContactFieldDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactFieldDto> {
        if (roomPhones.isEmpty() && devicePhones.isEmpty()) return emptyList()
        if (roomPhones.isEmpty()) return devicePhones
        if (devicePhones.isEmpty()) return roomPhones

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> devicePhones
            else -> roomPhones
        }
    }

    fun mergeAddressList(
        roomAddresses: List<ContactAddressDto>,
        deviceAddresses: List<ContactAddressDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactAddressDto> {
        if (roomAddresses.isEmpty() && deviceAddresses.isEmpty()) return emptyList()
        if (roomAddresses.isEmpty()) return deviceAddresses
        if (deviceAddresses.isEmpty()) return roomAddresses

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceAddresses
            else -> roomAddresses
        }
    }

    fun mergeImList(
        roomIms: List<ContactImDto>,
        deviceIms: List<ContactImDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactImDto> {
        if (roomIms.isEmpty() && deviceIms.isEmpty()) return emptyList()
        if (roomIms.isEmpty()) return deviceIms
        if (deviceIms.isEmpty()) return roomIms

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceIms
            else -> roomIms
        }
    }

    fun mergeWebsiteList(
        roomWebsites: List<ContactUrlDto>,
        deviceWebsites: List<ContactUrlDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactUrlDto> {
        if (roomWebsites.isEmpty() && deviceWebsites.isEmpty()) return emptyList()
        if (roomWebsites.isEmpty()) return deviceWebsites
        if (deviceWebsites.isEmpty()) return roomWebsites

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceWebsites
            else -> roomWebsites
        }
    }

    fun mergeRelationList(
        roomRelations: List<ContactRelationDto>,
        deviceRelations: List<ContactRelationDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactRelationDto> {
        if (roomRelations.isEmpty() && deviceRelations.isEmpty()) return emptyList()
        if (roomRelations.isEmpty()) return deviceRelations
        if (deviceRelations.isEmpty()) return roomRelations

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceRelations
            else -> roomRelations
        }
    }

    fun mergeEventList(
        roomEvents: List<ContactEventDto>,
        deviceEvents: List<ContactEventDto>,
        roomUpdatedAtEpochMs: Long?,
        deviceUpdatedAtEpochMs: Long?,
    ): List<ContactEventDto> {
        if (roomEvents.isEmpty() && deviceEvents.isEmpty()) return emptyList()
        if (roomEvents.isEmpty()) return deviceEvents
        if (deviceEvents.isEmpty()) return roomEvents

        val winner = DeviceContactConflictResolver.resolve(roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
        return when (winner) {
            Winner.DEVICE -> deviceEvents
            else -> roomEvents
        }
    }
}
