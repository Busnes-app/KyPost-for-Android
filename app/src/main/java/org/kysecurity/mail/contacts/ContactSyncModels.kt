package org.kysecurity.mail.contacts

import kotlinx.serialization.Serializable

/** Matches Mobile_Contact_Sync.md's Contact JSON shape exactly. */
@Serializable
data class ContactDto(
    val uid: String = "",
    val rev: Long = 0,
    val deleted: Boolean = false,
    val createdAt: String? = null,
    val updatedAt: String? = null,
    val fn: String = "",
    val givenName: String? = null,
    val familyName: String? = null,
    val middleName: String? = null,
    val prefix: String? = null,
    val suffix: String? = null,
    val nickname: String? = null,
    val org: String? = null,
    val title: String? = null,
    val notes: String? = null,
    val birthday: String? = null,
    val emails: List<ContactFieldDto> = emptyList(),
    val phones: List<ContactFieldDto> = emptyList(),
    val addresses: List<ContactAddressDto> = emptyList(),
    val groupIDs: List<String> = emptyList(),
    val photoRef: String? = null,
    val pgpKey: String? = null,
    /** Outbox-only consent for a Bring replay; never adopted from synced contact rows. */
    val omitUnusableKey: Boolean = false,
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
    val customFields: List<ContactCustomFieldDto> = emptyList(),
    val pronouns: String? = null,
    val isSelf: Boolean = false,
)

@Serializable
data class ContactFieldDto(
    val label: String? = null,
    val value: String = "",
)

@Serializable
data class ContactAddressDto(
    val label: String? = null,
    val street: String? = null,
    val city: String? = null,
    val region: String? = null,
    val postalCode: String? = null,
    val country: String? = null,
)

@Serializable
data class ContactImDto(
    val service: String? = null,
    val label: String? = null,
    val value: String = "",
)

@Serializable
data class ContactUrlDto(
    val label: String? = null,
    val value: String = "",
)

@Serializable
data class ContactRelationDto(
    val label: String? = null,
    val name: String = "",
)

@Serializable
data class ContactEventDto(
    val label: String? = null,
    val date: String = "",
)

@Serializable
data class ContactCustomFieldDto(
    val label: String = "",
    val value: String = "",
)

@Serializable
data class ContactSyncPullResponseDto(
    val cursor: Long = 0,
    val tooOld: Boolean = false,
    val changed: List<ContactDto> = emptyList(),
    val deleted: List<ContactDto> = emptyList(),
)

@Serializable
data class ContactSyncPushRequestDto(
    val baseCursor: Long,
    val changes: List<ContactDto>,
)

@Serializable
data class ContactDedupeReportDto(
    val mergedCount: Int = 0,
    val groups: List<ContactDedupeGroupDto> = emptyList(),
)

@Serializable
data class ContactDedupeGroupDto(
    val survivor: String = "",
    val absorbed: List<String> = emptyList(),
)
