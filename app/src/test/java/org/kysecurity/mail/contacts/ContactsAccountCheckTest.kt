package org.kysecurity.mail.contacts

import org.junit.Assert.assertEquals
import org.junit.Test
import org.kysecurity.mail.push.ReconnectExpectation

/** Owner decision Q2: contacts held for another account, or made while unpaired, are never
 *  uploaded before the user answers "Bring your N contacts into …?". */
class ContactsAccountCheckTest {
    private val a = ReconnectExpectation("sub-a", "https://a.example")
    private val b = ReconnectExpectation("sub-b", "https://b.example")

    @Test
    fun theOwnersContactsSync() {
        assertEquals(ContactsAccountCheck.PROCEED, contactsAccountCheck(a, a, holdsContacts = true, syncedWithCurrent = false))
    }

    @Test
    fun anotherAccountsContactsWaitForTheAnswer() {
        assertEquals(ContactsAccountCheck.ASK, contactsAccountCheck(a, b, holdsContacts = true, syncedWithCurrent = false))
        // The same subscriber id on another server is another account.
        assertEquals(ContactsAccountCheck.ASK, contactsAccountCheck(a, a.copy(serverUrl = "https://c.example"), true, false))
    }

    @Test
    fun contactsMadeWhileUnpairedWaitForTheAnswer() {
        assertEquals(ContactsAccountCheck.ASK, contactsAccountCheck(null, b, holdsContacts = true, syncedWithCurrent = false))
    }

    @Test
    fun nothingHeldIsAdoptedWithoutAQuestion() {
        assertEquals(ContactsAccountCheck.ADOPT, contactsAccountCheck(a, b, holdsContacts = false, syncedWithCurrent = false))
        assertEquals(ContactsAccountCheck.ADOPT, contactsAccountCheck(null, b, holdsContacts = false, syncedWithCurrent = false))
    }

    /** An install that synced before the owner was recorded must not be asked about its own contacts. */
    @Test
    fun anUpgradedInstallKeepsSyncing() {
        assertEquals(ContactsAccountCheck.ADOPT, contactsAccountCheck(null, a, holdsContacts = true, syncedWithCurrent = true))
    }
}
