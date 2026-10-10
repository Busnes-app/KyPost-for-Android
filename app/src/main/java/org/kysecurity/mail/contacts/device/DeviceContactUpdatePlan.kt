package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactFieldDto

/**
 * What pushing a [ContactDto] into an already-linked device raw contact has to write.
 *
 * A null member means the device row already carries the merged value, so the batch must not
 * touch it. Kept free of ContentProvider types so the decision is testable on the JVM.
 */
data class DeviceContactUpdatePlan(
    val displayName: String? = null,
    val org: String? = null,
    val notes: String? = null,
    val birthday: String? = null,
    val emails: List<ContactFieldDto>? = null,
    val phones: List<ContactFieldDto>? = null,
    val addresses: List<ContactAddressDto>? = null,
) {
    fun isEmpty(): Boolean = displayName == null && org == null && notes == null &&
        birthday == null && emails == null && phones == null && addresses == null

    /** True when applying this plan to [snapshot] leaves the phone with [dto]'s value for every
     *  field the plan covers: only then do both sides hold the same thing, the merge base. */
    fun leavesDeviceMatching(dto: ContactDto, snapshot: DeviceRawContactSnapshot): Boolean {
        fun <T> after(planned: T?, device: T): T = planned ?: device
        return listOf(
            after(displayName, snapshot.fn) to dto.fn,
            after(org, snapshot.org) to dto.org,
            after(notes, snapshot.notes) to dto.notes,
            after(birthday, snapshot.birthday) to dto.birthday,
            after(emails, snapshot.emails) to dto.emails,
            after(phones, snapshot.phones) to dto.phones,
            after(addresses, snapshot.addresses) to dto.addresses,
        ).all { (device, room) -> DeviceContactFieldMerge.same(device, room) }
    }

    companion object {
        /**
         * Runs the same merge as the device pull, against the same [base], then keeps only the
         * groups whose merged value differs from what the device already holds. An empty string
         * or list is a clear: Room emptied a field the device still has, since the last sync.
         */
        fun of(
            dto: ContactDto,
            snapshot: DeviceRawContactSnapshot,
            roomUpdatedAtEpochMs: Long?,
            deviceUpdatedAtEpochMs: Long?,
            base: ContactDto? = null,
        ): DeviceContactUpdatePlan {
            fun <T> merged(field: (ContactDto) -> T, device: T, twoWay: (T, T, Long?, Long?) -> T): T =
                DeviceContactFieldMerge.againstBase(field(dto), device, base?.let(field), base != null) { r, d ->
                    twoWay(r, d, roomUpdatedAtEpochMs, deviceUpdatedAtEpochMs)
                }

            // "" is a clear: only a known base can produce one, since two-way never empties a side.
            fun mergedString(field: (ContactDto) -> String?, deviceValue: String?): String? =
                merged(field, deviceValue, DeviceContactFieldMerge::mergeStringField)
                    .let { if (DeviceContactFieldMerge.same(it, deviceValue)) null else it.orEmpty() }

            fun <T> mergedList(field: (ContactDto) -> List<T>, deviceValue: List<T>, twoWay: (List<T>, List<T>, Long?, Long?) -> List<T>) =
                merged(field, deviceValue, twoWay).takeIf { it != deviceValue }

            return DeviceContactUpdatePlan(
                displayName = mergedString({ it.fn }, snapshot.fn),
                org = mergedString({ it.org }, snapshot.org),
                notes = mergedString({ it.notes }, snapshot.notes),
                birthday = mergedString({ it.birthday }, snapshot.birthday),
                emails = mergedList({ it.emails }, snapshot.emails, DeviceContactFieldMerge::mergeEmailList),
                phones = mergedList({ it.phones }, snapshot.phones, DeviceContactFieldMerge::mergePhoneList),
                addresses = mergedList({ it.addresses }, snapshot.addresses, DeviceContactFieldMerge::mergeAddressList),
            )
        }
    }
}
