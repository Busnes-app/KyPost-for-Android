package org.kysecurity.mail.contacts.device

import org.junit.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals

class ImportSourceKeyTest {
    private val google = DeviceAccount("com.google", "me@example.com")

    /** A resync gives the same server contact a new raw contact id; it is still the same source. */
    @Test
    fun aSyncedAccountsRowIsKeyedOnItsServerId_notItsRowId() {
        assertEquals(importSourceKey(google, "abc", 1), importSourceKey(google, "abc", 2))
    }

    @Test
    fun aRowWithoutAServerIdIsKeyedOnItsRowId() {
        val phone = DeviceAccount(null, null)
        assertEquals(importSourceKey(phone, null, 5), importSourceKey(phone, "", 5))
        assertNotEquals(importSourceKey(phone, null, 5), importSourceKey(phone, null, 6))
    }

    @Test
    fun theSameServerIdInTwoAccountsIsTwoSources() {
        assertNotEquals(importSourceKey(google, "abc", 1), importSourceKey(google.copy(name = "other@example.com"), "abc", 1))
        assertNotEquals(importSourceKey(google, "5", 1), importSourceKey(google, null, 5))
    }
}
