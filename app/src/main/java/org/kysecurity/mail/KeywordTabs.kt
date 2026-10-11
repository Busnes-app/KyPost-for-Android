package org.kysecurity.mail

object KeywordTabs {
    const val ALL = "All"

    fun buildTabs(emails: List<Email>): List<String> {
        val keywords = emails
            .flatMap { it.keywords }
            .filter { it.isNotBlank() }
            .distinct()
            .sortedBy { it.lowercase() }
        return listOf(ALL) + keywords
    }

    /** The inbox's tab strip: All first unless the user hid it, then the visible keywords. */
    fun visibleTabs(showAll: Boolean, keywords: List<String>): List<String> =
        (if (showAll) listOf(ALL) else emptyList()) + keywords

    /** Unread rows per tab, [ALL] included, in one pass over [emails]. */
    fun unreadCounts(emails: List<Email>): Map<String, Int> {
        val counts = HashMap<String, Int>()
        emails.filter { it.status == "unread" }.forEach { email ->
            (email.keywords + ALL).forEach { counts.merge(it, 1, Int::plus) }
        }
        return counts
    }

    /** Unread rows in [folder] and every folder below it. */
    fun unreadInFolderTree(counts: Map<String, Int>, folder: String): Int =
        counts.entries.sumOf { (path, unread) -> if (path == folder || path.startsWith("$folder/")) unread else 0 }

    fun filterEmails(emails: List<Email>, selectedTab: String): List<Email> {
        if (selectedTab == ALL) {
            return emails
        }
        return emails.filter { it.keywords.contains(selectedTab) }
    }
}

