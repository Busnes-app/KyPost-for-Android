package org.kysecurity.mail.push

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.security.EncryptedStoreUnavailableException
import kotlin.test.assertFailsWith

class MfaLockStoreReadTest {

    @Test
    fun anUnopenableLockStoreReadsAsNothingRatherThanThrowing() {
        val read = readUnlessLockStoreUnavailable<Boolean> {
            throw EncryptedStoreUnavailableException("app_lock_secure", RuntimeException("keystore"))
        }
        assertNull(read)
    }

    @Test
    fun aReadableStoreIsPassedThrough() {
        assertEquals(true, readUnlessLockStoreUnavailable { true })
    }

    @Test
    fun otherFailuresAreNotSwallowed() {
        assertFailsWith<IllegalArgumentException> {
            readUnlessLockStoreUnavailable<Boolean> { throw IllegalArgumentException("bug") }
        }
    }
}
