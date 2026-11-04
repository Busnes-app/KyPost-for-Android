package org.kysecurity.mail.contacts

import org.kysecurity.mail.push.ReconnectExpectation

/** Which account the contacts on this device belong to (owner decision Q2): an unpair can keep
 *  them, and pairing another account asks before they are uploaded there. Stored with the pairing
 *  proof (`SecurePairingStore`), but outlives an unpair that keeps contacts. */
interface ContactsOwnerStore {
    fun contactsOwner(): ReconnectExpectation?
    fun setContactsOwner(owner: ReconnectExpectation?)
}

/** "Bring your [count] contacts into [account]?" */
data class KeptContactsQuestion(val count: Int, val account: ReconnectExpectation)

enum class ContactsAccountCheck {
    /** The contacts are this account's: sync. */
    PROCEED,

    /** Nothing held that another account could own, or an install that synced with this account
     *  before the owner was recorded: record this account and sync. */
    ADOPT,

    /** Contacts held for another account, or made while unpaired: ask before uploading anything. */
    ASK,
}

fun contactsAccountCheck(
    owner: ReconnectExpectation?,
    current: ReconnectExpectation,
    holdsContacts: Boolean,
    syncedWithCurrent: Boolean,
): ContactsAccountCheck = when {
    owner == current -> ContactsAccountCheck.PROCEED
    !holdsContacts -> ContactsAccountCheck.ADOPT
    owner == null && syncedWithCurrent -> ContactsAccountCheck.ADOPT
    else -> ContactsAccountCheck.ASK
}
