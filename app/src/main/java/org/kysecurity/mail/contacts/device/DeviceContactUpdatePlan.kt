package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto

/**
 * What pushing a [ContactDto] into an already-linked device raw contact has to write: every
 * field `createRawContactForDto` maps, so an edit to any of them reaches the phone.
 *
 * A null member means the device row already carries the merged value, so the batch must not
 * touch it. Kept free of ContentProvider types so the decision is testable on the JVM.
 */
data class DeviceContactUpdatePlan(
    val displayName: String? = null,
    val givenName: String? = null,
    val familyName: String? = null,
    val middleName: String? = null,
    val prefix: String? = null,
    val suffix: String? = null,
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val org: String? = null,
    val title: String? = null,
    val department: String? = null,
    val notes: String? = null,
    val birthday: String? = null,
    val emails: List<ContactFieldDto>? = null,
    val phones: List<ContactFieldDto>? = null,
    val addresses: List<ContactAddressDto>? = null,
    val ims: List<ContactImDto>? = null,
    val websites: List<ContactUrlDto>? = null,
    val relations: List<ContactRelationDto>? = null,
    val events: List<ContactEventDto>? = null,
) {
    fun isEmpty(): Boolean = this == DeviceContactUpdatePlan()

    /** The StructuredName row has a change. */
    fun hasNameChange(): Boolean = listOf(
        displayName, givenName, familyName, middleName, prefix, suffix, phoneticGivenName, phoneticFamilyName,
    ).any { it != null }

    /** The Organization row has a change; it holds all three. */
    fun hasOrganizationChange(): Boolean = org != null || title != null || department != null

    /** True when applying this plan to [snapshot] leaves the phone with [dto]'s value for every
     *  merged field. */
    fun leavesDeviceMatching(dto: ContactDto, snapshot: DeviceRawContactSnapshot): Boolean =
        nextBase(dto, snapshot, base = null) != null

    /** The merge base once this plan lands: [dto]'s value for each field the phone will then hold
     *  too, [base]'s for the rest. Without a [base], null unless every field agrees. */
    fun nextBase(dto: ContactDto, snapshot: DeviceRawContactSnapshot, base: ContactDto?): ContactDto? {
        val old = base ?: dto
        var disagreed = false
        fun <T> pick(planned: T?, device: T, room: T, previous: T): T =
            if (DeviceContactFieldMerge.same(planned ?: device, room)) room else previous.also { disagreed = true }
        val next = dto.copy(
            fn = pick(displayName, snapshot.fn, dto.fn, old.fn),
            givenName = pick(givenName, snapshot.givenName, dto.givenName, old.givenName),
            familyName = pick(familyName, snapshot.familyName, dto.familyName, old.familyName),
            middleName = pick(middleName, snapshot.middleName, dto.middleName, old.middleName),
            prefix = pick(prefix, snapshot.prefix, dto.prefix, old.prefix),
            suffix = pick(suffix, snapshot.suffix, dto.suffix, old.suffix),
            phoneticGivenName = pick(phoneticGivenName, snapshot.phoneticGivenName, dto.phoneticGivenName, old.phoneticGivenName),
            phoneticFamilyName = pick(phoneticFamilyName, snapshot.phoneticFamilyName, dto.phoneticFamilyName, old.phoneticFamilyName),
            org = pick(org, snapshot.org, dto.org, old.org),
            title = pick(title, snapshot.title, dto.title, old.title),
            department = pick(department, snapshot.department, dto.department, old.department),
            notes = pick(notes, snapshot.notes, dto.notes, old.notes),
            birthday = pick(birthday, snapshot.birthday, dto.birthday, old.birthday),
            emails = pick(emails, snapshot.emails, dto.emails, old.emails),
            phones = pick(phones, snapshot.phones, dto.phones, old.phones),
            addresses = pick(addresses, snapshot.addresses, dto.addresses, old.addresses),
            ims = pick(ims, snapshot.ims, dto.ims, old.ims),
            websites = pick(websites, snapshot.websites, dto.websites, old.websites),
            relations = pick(relations, snapshot.relations, dto.relations, old.relations),
            events = pick(events, snapshot.events, dto.events, old.events),
        )
        return next.takeUnless { base == null && disagreed }
    }

    companion object {
        /**
         * Runs the same merge as the device pull, against the same [base], then keeps only the
         * fields whose merged value differs from what the device already holds. An empty string
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
                merged(field, deviceValue, twoWay).takeUnless { DeviceContactFieldMerge.same(it, deviceValue) }

            return DeviceContactUpdatePlan(
                displayName = mergedString({ it.fn }, snapshot.fn),
                givenName = mergedString({ it.givenName }, snapshot.givenName),
                familyName = mergedString({ it.familyName }, snapshot.familyName),
                middleName = mergedString({ it.middleName }, snapshot.middleName),
                prefix = mergedString({ it.prefix }, snapshot.prefix),
                suffix = mergedString({ it.suffix }, snapshot.suffix),
                phoneticGivenName = mergedString({ it.phoneticGivenName }, snapshot.phoneticGivenName),
                phoneticFamilyName = mergedString({ it.phoneticFamilyName }, snapshot.phoneticFamilyName),
                org = mergedString({ it.org }, snapshot.org),
                title = mergedString({ it.title }, snapshot.title),
                department = mergedString({ it.department }, snapshot.department),
                notes = mergedString({ it.notes }, snapshot.notes),
                birthday = mergedString({ it.birthday }, snapshot.birthday),
                emails = mergedList({ it.emails }, snapshot.emails, DeviceContactFieldMerge::mergeEmailList),
                phones = mergedList({ it.phones }, snapshot.phones, DeviceContactFieldMerge::mergePhoneList),
                addresses = mergedList({ it.addresses }, snapshot.addresses, DeviceContactFieldMerge::mergeAddressList),
                ims = mergedList({ it.ims }, snapshot.ims, DeviceContactFieldMerge::mergeImList),
                websites = mergedList({ it.websites }, snapshot.websites, DeviceContactFieldMerge::mergeWebsiteList),
                relations = mergedList({ it.relations }, snapshot.relations, DeviceContactFieldMerge::mergeRelationList),
                events = mergedList({ it.events }, snapshot.events, DeviceContactFieldMerge::mergeEventList),
            )
        }
    }
}
