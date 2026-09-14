package org.kysecurity.mail.security

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class OwnedAttachmentSaveTest {
    @Test
    fun snapshotSurvivesCleanupAndIsAlwaysWipedBeforeAnotherAdmission() {
        val owner = OwnedAttachmentSave()
        val source = byteArrayOf(1, 2, 3)
        owner.allow()

        val snapshot = owner.admit(source, lifecycleValid = true)!!
        source.fill(0) // lock clears the UI-owned source
        owner.stopAccepting()

        assertArrayEquals(byteArrayOf(1, 2, 3), snapshot)
        assertNull(owner.admit(byteArrayOf(4), lifecycleValid = true))
        owner.finish(snapshot)
        assertTrue(snapshot.all { it == 0.toByte() })

        owner.allow()
        val rejectedSnapshot = owner.admit(byteArrayOf(5), lifecycleValid = true)!!
        owner.finish(rejectedSnapshot) // executor rejection follows this path
        assertTrue(rejectedSnapshot.all { it == 0.toByte() })
        assertNull(owner.admit(byteArrayOf(6), lifecycleValid = false))
    }
}
