package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class MoveToFolderTest {

    @Test
    fun offersInboxTopLevelAndArchiveSubfolders() {
        assertEquals(
            listOf("INBOX", "Junk", "Sent", "Archive/2025", "Archive/Receipts"),
            moveTargets("Trash", listOf("Junk", "Sent", "Trash"), listOf("Archive/2025", "Archive/Receipts")),
        )
    }

    @Test
    fun neverOffersTheFolderTheMailIsIn() {
        assertEquals(listOf("Junk"), moveTargets("INBOX", listOf("Junk"), emptyList()))
        assertEquals(listOf("INBOX"), moveTargets("archive/2025", emptyList(), listOf("Archive/2025")))
    }

    @Test
    fun aFolderListedTwiceIsOfferedOnce() {
        assertEquals(listOf("INBOX", "Sent"), moveTargets("Junk", listOf("Sent", "SENT", "inbox"), emptyList()))
    }
}
