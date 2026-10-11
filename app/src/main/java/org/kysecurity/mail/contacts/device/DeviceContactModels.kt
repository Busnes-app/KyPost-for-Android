package org.kysecurity.mail.contacts.device

import org.kysecurity.mail.contacts.ContactAddressDto
import org.kysecurity.mail.contacts.ContactEventDto
import org.kysecurity.mail.contacts.ContactFieldDto
import org.kysecurity.mail.contacts.ContactImDto
import org.kysecurity.mail.contacts.ContactRelationDto
import org.kysecurity.mail.contacts.ContactUrlDto

// No groupIDs on the read side: group membership only ever flows Room -> device.
data class DeviceRawContactSnapshot(
    val rawContactId: Long,
    val contactId: Long,
    val accountType: String?,
    val accountName: String?,
    val lastUpdatedEpochMs: Long,
    val dirty: Boolean,
    val fn: String,
    val org: String?,
    val notes: String?,
    val birthday: String?,
    val emails: List<ContactFieldDto>,
    val phones: List<ContactFieldDto>,
    val addresses: List<ContactAddressDto>,
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
    val title: String? = null,
    /** The phone's own TYPE/LABEL per IM, keyed by [keptTypeKey] of the protocol the rebuild
     *  writes, in row order for duplicates: device-only, kept so a rebuild does not drop it. */
    val imTypes: Map<String, List<Pair<Int?, String?>>> = emptyMap(),
    /** As [imTypes], per website label and URL. */
    val websiteTypes: Map<String, List<Pair<Int?, String?>>> = emptyMap(),
    val givenName: String? = null,
    val familyName: String? = null,
    val middleName: String? = null,
    val prefix: String? = null,
    val suffix: String? = null,
)

data class DeviceContactCandidate(
    val contactId: Long,
    val rawContactId: Long,
    val lastUpdatedEpochMs: Long,
    val emails: List<String>,
    val phones: List<String>,
    val fn: String,
    val org: String?,
    val notes: String?,
)

// The write side, so it does carry groupIDs; pgpKey/pronouns/customFields have no CP2 data kind.
data class DeviceFieldSet(
    val fn: String,
    val givenName: String?,
    val familyName: String?,
    val middleName: String?,
    val prefix: String?,
    val suffix: String?,
    val nickname: String?,
    val org: String?,
    val title: String?,
    val notes: String?,
    val birthday: String?,
    val emails: List<ContactFieldDto>,
    val phones: List<ContactFieldDto>,
    val addresses: List<ContactAddressDto>,
    val groupIDs: List<String> = emptyList(),
    val ims: List<ContactImDto> = emptyList(),
    val websites: List<ContactUrlDto> = emptyList(),
    val relations: List<ContactRelationDto> = emptyList(),
    val events: List<ContactEventDto> = emptyList(),
    val phoneticGivenName: String? = null,
    val phoneticFamilyName: String? = null,
    val department: String? = null,
)

/** One row's identity on the phone: what tells it apart besides its value (an IM's protocol, a
 *  website's label) and the value. The same value on two services is two IMs. */
internal fun keptTypeKey(qualifier: String?, value: String): String = "${qualifier.orEmpty()}\n$value"
