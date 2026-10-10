package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** Paths as `GET /api/inbox/folders` (no parent) returns them: top level, INBOX and Archive
 *  omitted, the account's own delimiter and spelling. */
class SpecialFolderTest {

    @Test
    fun resolvesTheAccountsOwnSpelling() {
        val dovecot = listOf("INBOX.Drafts", "INBOX.Junk", "INBOX.Sent", "INBOX.Trash")
        assertEquals("INBOX.Sent", resolveSpecialFolder(dovecot, SpecialFolder.SENT))
        assertEquals("INBOX.Drafts", resolveSpecialFolder(dovecot, SpecialFolder.DRAFTS))

        val exchange = listOf("Deleted Items", "Drafts", "Junk Email", "Sent Items")
        assertEquals("Sent Items", resolveSpecialFolder(exchange, SpecialFolder.SENT))
    }

    @Test
    fun prefersTheServersFirstAlias() {
        val both = listOf("Sent Messages", "Sent")
        assertEquals("Sent", resolveSpecialFolder(both, SpecialFolder.SENT))
    }

    @Test
    fun aLookalikeIsNotTheFolder() {
        assertNull(resolveSpecialFolder(listOf("Unsent", "Sentinel", "Projects/Draftsmanship"), SpecialFolder.SENT))
        assertNull(resolveSpecialFolder(listOf("Unsent", "Sentinel", "Projects/Draftsmanship"), SpecialFolder.DRAFTS))
    }

    @Test
    fun missingFolderIsNull() {
        assertNull(resolveSpecialFolder(listOf("Junk", "Trash"), SpecialFolder.DRAFTS))
    }

    @Test
    fun labelsFollowTheLeaf() {
        assertEquals(SpecialFolder.SENT, specialFolderOf("INBOX.Sent"))
        assertEquals(SpecialFolder.SENT, specialFolderOf("Sent Items"))
        assertEquals(SpecialFolder.DRAFTS, specialFolderOf("drafts"))
        assertNull(specialFolderOf("INBOX"))
        assertNull(specialFolderOf("Junk"))
    }
}
