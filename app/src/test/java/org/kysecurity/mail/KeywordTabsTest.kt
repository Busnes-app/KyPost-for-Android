package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Test

class KeywordTabsTest {

    @Test
    fun buildTabs_placesAllFirst_andSortsKeywords() {
        val emails = listOf(
            Email(id = "1", subject = "A", sender = "a", preview = "p", keywords = setOf("Travel", "Finance")),
            Email(id = "2", subject = "B", sender = "b", preview = "p", keywords = setOf("Important")),
            Email(id = "3", subject = "C", sender = "c", preview = "p", keywords = setOf("finance")),
        )

        val tabs = KeywordTabs.buildTabs(emails)

        assertEquals(listOf("All", "Finance", "finance", "Important", "Travel"), tabs)
    }

    @Test
    fun visibleTabs_putsAllFirst_whenShown() {
        assertEquals(listOf("All", "Finance"), KeywordTabs.visibleTabs(showAll = true, keywords = listOf("Finance")))
    }

    @Test
    fun visibleTabs_omitsAll_whenHidden() {
        assertEquals(listOf("Finance"), KeywordTabs.visibleTabs(showAll = false, keywords = listOf("Finance")))
    }

    @Test
    fun filterEmails_returnsOnlyMatchingKeyword() {
        val emails = listOf(
            Email(id = "1", subject = "A", sender = "a", preview = "p", keywords = setOf("Finance")),
            Email(id = "2", subject = "B", sender = "b", preview = "p", keywords = setOf("Travel")),
        )

        val filtered = KeywordTabs.filterEmails(emails, "Travel")

        assertEquals(listOf("2"), filtered.map { it.id })
    }

    @Test
    fun unreadCountCountsUnreadRowsInTheTab() {
        val emails = listOf(
            Email(id = "1", subject = "s", sender = "a", preview = "", keywords = setOf("Work"), status = "unread"),
            Email(id = "2", subject = "s", sender = "a", preview = "", keywords = setOf("Work"), status = "read"),
            Email(id = "3", subject = "s", sender = "a", preview = "", keywords = setOf("Home"), status = "unread"),
        )

        assertEquals(mapOf("Work" to 1, "Home" to 1, KeywordTabs.ALL to 2), KeywordTabs.unreadCounts(emails))
    }

    /** Archive's entry stands for its subfolders too; a sibling sharing the prefix does not count. */
    @Test
    fun unreadInFolderTreeSumsTheFolderAndItsSubfolders() {
        val counts = mapOf("Archive" to 1, "Archive/2025" to 2, "Archive/2025/Q1" to 3, "ArchiveOld" to 7, "INBOX" to 9)

        assertEquals(6, KeywordTabs.unreadInFolderTree(counts, "Archive"))
        assertEquals(0, KeywordTabs.unreadInFolderTree(counts, "Trash"))
    }

    /** The picker follows a read, an unread, or a row leaving the folder until Room is re-read. */
    @Test
    fun adjustedUnreadFollowsOneRowsChange() {
        val counts = mapOf("INBOX" to 2, "Junk" to 1)

        assertEquals(mapOf("INBOX" to 1, "Junk" to 1), KeywordTabs.adjustedUnread(counts, "INBOX", "unread", "read"))
        assertEquals(mapOf("INBOX" to 3, "Junk" to 1), KeywordTabs.adjustedUnread(counts, "INBOX", "read", "unread"))
        assertEquals(mapOf("INBOX" to 2, "Junk" to 0), KeywordTabs.adjustedUnread(counts, "Junk", "unread", null))
        assertEquals(counts, KeywordTabs.adjustedUnread(counts, "INBOX", "read", null))
        assertEquals(mapOf("INBOX" to 2, "Junk" to 1, "Trash" to 0), KeywordTabs.adjustedUnread(counts, "Trash", "unread", null))
    }
}
