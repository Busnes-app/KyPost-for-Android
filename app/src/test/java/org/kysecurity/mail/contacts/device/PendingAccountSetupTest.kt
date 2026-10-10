package org.kysecurity.mail.contacts.device

import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

/** Every add-account request gets exactly one answer, so no caller is left waiting. */
class PendingAccountSetupTest {
    private val answers = mutableListOf<String>()

    private fun hold(tag: String) = PendingAccountSetup.hold(
        onAdded = { answers += "$tag added $it" },
        onCancelled = { answers += "$tag cancelled" },
    )

    @AfterTest
    fun clear() = PendingAccountSetup.cancel()

    @Test
    fun completingAnswersOnce() {
        hold("a")
        PendingAccountSetup.complete("KyPost")
        PendingAccountSetup.complete("KyPost")
        PendingAccountSetup.cancel()

        assertEquals(listOf("a added KyPost"), answers)
        assertFalse(PendingAccountSetup.isPending)
    }

    @Test
    fun aNewRequestCancelsTheOldOne() {
        hold("a")
        hold("b")
        PendingAccountSetup.complete("KyPost")

        assertEquals(listOf("a cancelled", "b added KyPost"), answers)
    }

    @Test
    fun aSessionResetCancels() {
        hold("a")
        PendingAccountSetup.resetForNewSession()

        assertEquals(listOf("a cancelled"), answers)
    }
}
