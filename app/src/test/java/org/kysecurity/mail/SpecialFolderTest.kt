package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.mail.FolderInfo

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

    /** The server's special-use flag is the only thing a localized name keeps. */
    @Test
    fun theServersSpecialUseFlagFindsALocalizedFolder() {
        val german = listOf(FolderInfo("Entwürfe", false, "drafts"), FolderInfo("Gesendet", false, "sent"))
        assertEquals("Gesendet", specialFolderPath(german, SpecialFolder.SENT))
        assertEquals("Entwürfe", specialFolderPath(german, SpecialFolder.DRAFTS))
        // Once opened it reads as Sent: title, picker tick.
        assertEquals(SpecialFolder.SENT, specialFolderOf("Gesendet"))
    }

    @Test
    fun theFlagBeatsAnEnglishLookalike() {
        val both = listOf(FolderInfo("Sent", true), FolderInfo("INBOX.Enviados", false, "sent"))
        assertEquals("INBOX.Enviados", specialFolderPath(both, SpecialFolder.SENT))
    }

    @Test
    fun withoutFlagsTheAliasesStillApply() {
        assertEquals("Sent Items", specialFolderPath(listOf(FolderInfo("Sent Items", false)), SpecialFolder.SENT))
        assertNull(specialFolderPath(listOf(FolderInfo("Gesendet", false)), SpecialFolder.SENT))
        // Snoozed has no role: an unflagged folder must not match it.
        assertNull(specialFolderPath(listOf(FolderInfo("Work", true)), SpecialFolder.SNOOZED))
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
        // Archived copies are Archive's: the picker must not tick Sent or Drafts for them.
        assertNull(specialFolderOf("Archive/Sent"))
        assertNull(specialFolderOf("Archive.Drafts"))
        // A user's own folder of that name, reachable from the folders screen.
        assertNull(specialFolderOf("Projects/Sent"))
        assertEquals(SpecialFolder.SNOOZED, specialFolderOf("Snoozed"))
        // The server's name is exact: a user's own lookalike keeps Snooze and stays a Move target.
        assertNull(specialFolderOf("INBOX/Snoozed"))
        assertNull(specialFolderOf("snoozed"))
        assertEquals("Snoozed", resolveSpecialFolder(listOf("snoozed", "Snoozed"), SpecialFolder.SNOOZED))
        assertEquals(SpecialFolder.DRAFTS, specialFolderOf("INBOX/Drafts"))
        assertNull(specialFolderOf("Junk"))
    }
}
