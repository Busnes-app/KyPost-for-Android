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

    /** IMAP flags and server keywords ($Phishing, $Junk, \Seen) are state, not the user's labels. */
    @Test
    fun buildTabs_dropsImapSystemKeywords() {
        val emails = listOf(
            Email(
                id = "1", subject = "A", sender = "a", preview = "p",
                keywords = setOf("\$Phishing", "\\Seen", "\$Junk", "Work"),
            ),
        )

        assertEquals(listOf("All", "Work"), KeywordTabs.buildTabs(emails))
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
}

