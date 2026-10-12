package org.kysecurity.mail.contacts.device

import android.provider.ContactsContract.CommonDataKinds.Email
import android.provider.ContactsContract.CommonDataKinds.Event
import android.provider.ContactsContract.CommonDataKinds.Phone
import android.provider.ContactsContract.CommonDataKinds.Relation
import android.provider.ContactsContract.CommonDataKinds.StructuredPostal

object DeviceContactFieldCoding {
    /** Mirrors the web frontend's IM_SERVICES catalog; every `ims` row is PROTOCOL_CUSTOM. */
    fun imCustomProtocolLabel(service: String?, label: String?): String = when (service) {
        "whatsapp" -> "WhatsApp"
        "signal" -> "Signal"
        "telegram" -> "Telegram"
        "instagram" -> "Instagram"
        "x" -> "X (Twitter)"
        "linkedin" -> "LinkedIn"
        "facebook" -> "Facebook"
        "mastodon" -> "Mastodon"
        "matrix" -> "Matrix"
        else -> label?.takeIf { it.isNotBlank() } ?: "Other"
    }

    /** Inverse of [imCustomProtocolLabel]; an unrecognized display string collapses to "" (other). */
    fun imServiceFromCustomProtocolLabel(label: String?): String = when (label) {
        "WhatsApp" -> "whatsapp"
        "Signal" -> "signal"
        "Telegram" -> "telegram"
        "Instagram" -> "instagram"
        "X (Twitter)" -> "x"
        "LinkedIn" -> "linkedin"
        "Facebook" -> "facebook"
        "Mastodon" -> "mastodon"
        "Matrix" -> "matrix"
        else -> ""
    }

    /** `Email.TYPE` is DATA2, an integer code — free text belongs in `Email.LABEL` (DATA3), so an
     *  unrecognized label gives TYPE_CUSTOM. Matched case-insensitively: the label is user-typed. */
    fun emailType(label: String?): Int = when (label?.trim()?.lowercase()) {
        "home" -> Email.TYPE_HOME
        "work" -> Email.TYPE_WORK
        "mobile" -> Email.TYPE_MOBILE
        "other" -> Email.TYPE_OTHER
        else -> Email.TYPE_CUSTOM
    }

    /** The `Email.LABEL` value to pair with [emailType], following the TYPE_CUSTOM+LABEL convention. */
    fun emailCustomLabel(label: String?): String? =
        if (emailType(label) == Email.TYPE_CUSTOM) label else null

    /** Inverse of [emailType]; null for TYPE_CUSTOM/unset so the caller falls back to `Email.LABEL`. */
    fun emailLabelFromType(type: Int?): String? = when (type) {
        Email.TYPE_HOME -> "Home"
        Email.TYPE_WORK -> "Work"
        Email.TYPE_MOBILE -> "Mobile"
        Email.TYPE_OTHER -> "Other"
        else -> null
    }

    /** As [emailType], for `Phone.TYPE`. */
    fun phoneType(label: String?): Int = when (label?.trim()?.lowercase()) {
        "home" -> Phone.TYPE_HOME
        "mobile" -> Phone.TYPE_MOBILE
        "work" -> Phone.TYPE_WORK
        "work fax" -> Phone.TYPE_FAX_WORK
        "home fax" -> Phone.TYPE_FAX_HOME
        "pager" -> Phone.TYPE_PAGER
        "main" -> Phone.TYPE_MAIN
        "other" -> Phone.TYPE_OTHER
        else -> Phone.TYPE_CUSTOM
    }

    /** The `Phone.LABEL` value to pair with [phoneType]. */
    fun phoneCustomLabel(label: String?): String? =
        if (phoneType(label) == Phone.TYPE_CUSTOM) label else null

    /** Inverse of [phoneType]; null for TYPE_CUSTOM/unset so the caller falls back to `Phone.LABEL`. */
    fun phoneLabelFromType(type: Int?): String? = when (type) {
        Phone.TYPE_HOME -> "Home"
        Phone.TYPE_MOBILE -> "Mobile"
        Phone.TYPE_WORK -> "Work"
        Phone.TYPE_FAX_WORK -> "Work Fax"
        Phone.TYPE_FAX_HOME -> "Home Fax"
        Phone.TYPE_PAGER -> "Pager"
        Phone.TYPE_MAIN -> "Main"
        Phone.TYPE_OTHER -> "Other"
        else -> null
    }

    /** As [emailType], for `StructuredPostal.TYPE`. */
    fun postalType(label: String?): Int = when (label?.trim()?.lowercase()) {
        "home" -> StructuredPostal.TYPE_HOME
        "work" -> StructuredPostal.TYPE_WORK
        "other" -> StructuredPostal.TYPE_OTHER
        else -> StructuredPostal.TYPE_CUSTOM
    }

    /** The `StructuredPostal.LABEL` value to pair with [postalType]. */
    fun postalCustomLabel(label: String?): String? =
        if (postalType(label) == StructuredPostal.TYPE_CUSTOM) label else null

    /** Inverse of [postalType]; null for TYPE_CUSTOM/unset so the caller falls back to the LABEL column. */
    fun postalLabelFromType(type: Int?): String? = when (type) {
        StructuredPostal.TYPE_HOME -> "Home"
        StructuredPostal.TYPE_WORK -> "Work"
        StructuredPostal.TYPE_OTHER -> "Other"
        else -> null
    }

    /** The label of a row whose TYPE is custom or unset: the LABEL column (DATA3), falling back to a
     *  non-numeric TYPE column (DATA2), where builds predating the TYPE/LABEL split wrote it. */
    fun customLabelOf(typeColumn: String?, labelColumn: String?): String? =
        labelColumn?.takeIf { it.isNotBlank() }
            ?: typeColumn?.takeIf { it.isNotBlank() && it.toIntOrNull() == null }

    /** Constants confirmed against the SDK's android.jar; unrecognized labels give TYPE_CUSTOM. */
    fun relationType(label: String?): Int = when (label) {
        "spouse" -> Relation.TYPE_SPOUSE
        "child" -> Relation.TYPE_CHILD
        "parent" -> Relation.TYPE_PARENT
        "partner" -> Relation.TYPE_PARTNER
        "manager" -> Relation.TYPE_MANAGER
        "assistant" -> Relation.TYPE_ASSISTANT
        "friend" -> Relation.TYPE_FRIEND
        "relative" -> Relation.TYPE_RELATIVE
        else -> Relation.TYPE_CUSTOM
    }

    /** The `Relation.LABEL` value to pair with [relationType] — only non-null when [relationType]
     *  resolved to `TYPE_CUSTOM`, matching the `TYPE_CUSTOM`+`LABEL` pairing convention. */
    fun relationCustomLabel(label: String?): String? =
        if (relationType(label) == Relation.TYPE_CUSTOM) label else null

    /** `label == "anniversary"` -> `Event.TYPE_ANNIVERSARY`; anything else -> `Event.TYPE_CUSTOM`.
     *  Birthday is unaffected — it stays the separate, existing `Event.TYPE_BIRTHDAY` row. */
    fun eventType(label: String?): Int = if (label == "anniversary") Event.TYPE_ANNIVERSARY else Event.TYPE_CUSTOM

    /** The `Event.LABEL` value to pair with [eventType] — only non-null when [eventType] resolved
     *  to `TYPE_CUSTOM`. */
    fun eventCustomLabel(label: String?): String? = if (eventType(label) == Event.TYPE_CUSTOM) label else null

    /** Inverse of [relationType] and [relationCustomLabel]: a custom type reads back its LABEL,
     *  and only a row with neither becomes "other". */
    fun relationLabelFromType(type: Int?, customLabel: String? = null): String = when (type) {
        Relation.TYPE_SPOUSE -> "spouse"
        Relation.TYPE_CHILD -> "child"
        Relation.TYPE_PARENT -> "parent"
        Relation.TYPE_PARTNER -> "partner"
        Relation.TYPE_MANAGER -> "manager"
        Relation.TYPE_ASSISTANT -> "assistant"
        Relation.TYPE_FRIEND -> "friend"
        Relation.TYPE_RELATIVE -> "relative"
        else -> customLabel?.takeIf { it.isNotBlank() } ?: "other"
    }

    /** Inverse of [eventType] for the recognized (`TYPE_ANNIVERSARY`) case only; returns null for
     *  everything else so the caller falls back to the row's free-text `Event.LABEL` column. */
    fun eventLabelFromType(type: Int?): String? = if (type == Event.TYPE_ANNIVERSARY) "anniversary" else null
}
