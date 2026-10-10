package org.kysecurity.mail

object KeywordTabs {
    const val ALL = "All"

    /** IMAP system flags (`\Seen`) and server keywords (`$Phishing`) are message state, not labels.
     *  They stay on [Email.keywords]: `isFlaggedPhishing` reads `$Phishing` from there. */
    fun isSystemKeyword(keyword: String): Boolean = keyword.startsWith('$') || keyword.startsWith('\\')

    fun buildTabs(emails: List<Email>): List<String> {
        val keywords = emails
            .flatMap { it.keywords }
            .filter { it.isNotBlank() && !isSystemKeyword(it) }
            .distinct()
            .sortedBy { it.lowercase() }
        return listOf(ALL) + keywords
    }

    /** The inbox's tab strip: All first unless the user hid it, then the visible keywords. */
    fun visibleTabs(showAll: Boolean, keywords: List<String>): List<String> =
        (if (showAll) listOf(ALL) else emptyList()) + keywords

    fun filterEmails(emails: List<Email>, selectedTab: String): List<Email> {
        if (selectedTab == ALL) {
            return emails
        }
        return emails.filter { it.keywords.contains(selectedTab) }
    }
}

