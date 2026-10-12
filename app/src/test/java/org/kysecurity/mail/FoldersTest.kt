package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.mail.FolderInfo

class FoldersTest {

    @Test
    fun aFolderNameIsOneLevelAndFree() {
        assertNull(folderNameProblem("Receipts 2026", listOf("Old")))
        assertEquals(R.string.folders_name_blank, folderNameProblem("  ", emptyList()))
        assertEquals(R.string.folders_name_delimiter, folderNameProblem("a/b", emptyList()))
        assertEquals(R.string.folders_name_delimiter, folderNameProblem("v1.2", emptyList()))
        assertEquals(R.string.folders_name_taken, folderNameProblem("old", listOf("Old")))
    }

    @Test
    fun theTopLevelAddsBackArchiveOnce() {
        val work = FolderInfo("Work", deletable = false)
        assertEquals(listOf("Archive", "Work"), withArchive("", listOf(work)).map { it.path })
        assertEquals(listOf("archive"), withArchive("", listOf(FolderInfo("archive", false))).map { it.path })
        assertEquals(listOf("Work"), withArchive("Archive", listOf(work)).map { it.path })
    }

    @Test
    fun theParentFollowsEitherDelimiter() {
        assertEquals("Archive", mailboxParent("Archive/2026"))
        assertEquals("INBOX.Work", mailboxParent("INBOX.Work.Old"))
        assertEquals("", mailboxParent("Work"))
    }

    @Test
    fun theOpenFolderFollowsARenameOrDeleteAboveIt() {
        assertEquals("Archive/New", movedOpenFolder("Archive/Old", "Archive/Old", "Archive/New"))
        assertEquals("INBOX.New.Sub", movedOpenFolder("INBOX.Old.Sub", "INBOX.Old", "INBOX.New"))
        assertEquals("Archive", movedOpenFolder("archive/old", "Archive/Old", "Archive"))
        // A sibling that merely shares the prefix is not inside it.
        assertNull(movedOpenFolder("Archive/Older", "Archive/Old", "Archive/New"))
        assertNull(movedOpenFolder(null, "Archive/Old", "Archive"))
    }
}
