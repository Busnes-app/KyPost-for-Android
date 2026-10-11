package org.kysecurity.mail.security

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** Offered once, only to a device without a lock, and never again once seen. */
class AppLockOfferTest {

    @Test
    fun anUnlockedDeviceIsOfferedOnce() {
        assertTrue(shouldOfferAppLock(lockEnabled = false, alreadyOffered = false))
        assertFalse(shouldOfferAppLock(lockEnabled = false, alreadyOffered = true))
    }

    @Test
    fun aDeviceWithALockIsNeverAsked() {
        assertFalse(shouldOfferAppLock(lockEnabled = true, alreadyOffered = false))
    }
}
