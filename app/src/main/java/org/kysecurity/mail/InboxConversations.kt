package org.kysecurity.mail

import org.kysecurity.mail.mail.Conversation

/** One inbox list row. A plain message has [members] = [email]. A conversation row stands where
 *  its newest shown member is; [members] are its loaded members in this folder, oldest first, and
 *  are what list actions act on. [nested] rows are the messages of an expanded conversation: they
 *  open, and nothing else. */
data class InboxRow(
    val email: Email,
    val members: List<Email> = listOf(email),
    val sent: List<Email> = emptyList(),
    val conversationId: String? = null,
    val expanded: Boolean = false,
    val nested: Boolean = false,
) {
    val isConversation: Boolean get() = conversationId != null && !nested
    val count: Int get() = members.size + sent.size
    val unread: Boolean get() = members.any { it.status == "unread" }

    /** Unique per list: an expanded conversation shows its lead twice, once [nested]. */
    val key: Triple<Boolean, String, String> get() = Triple(nested, email.folder, email.id)

    /** Redacted, as [Email] is. */
    override fun toString(): String = "InboxRow(redacted)"
}

/** Folds [shown] (the filtered, sorted rows) into conversation rows. Members come from
 *  [folderRows], every loaded row of the folder, so a keyword tab never splits what an action
 *  covers. A group with fewer than two loaded messages is a plain row. Expanded conversations are
 *  followed by their messages, your replies included, oldest first. */
internal fun groupInboxRows(
    shown: List<Email>,
    folderRows: List<Email>,
    conversations: List<Conversation>,
    expanded: Set<String>,
): List<InboxRow> {
    if (conversations.isEmpty()) return shown.map(::InboxRow)
    val byMessage = HashMap<String, Conversation>()
    conversations.forEach { c -> c.messageIds.forEach { byMessage[it] = c } }
    val loaded = folderRows.associateBy { it.id }
    val placed = HashSet<String>()
    val out = ArrayList<InboxRow>(shown.size)
    for (lead in shown) {
        val conversation = byMessage[lead.id]
        if (conversation == null) {
            out += InboxRow(lead)
            continue
        }
        if (!placed.add(conversation.id)) continue
        val members = conversation.messageIds.mapNotNull(loaded::get)
        if (members.size + conversation.sent.size < 2) {
            out += InboxRow(lead)
            continue
        }
        val open = conversation.id in expanded
        out += InboxRow(lead, members, conversation.sent, conversation.id, expanded = open)
        if (open) {
            (members + conversation.sent).sortedBy { it.atUtc.orEmpty() }
                .forEach { out += InboxRow(it, nested = true) }
        }
    }
    return out
}

/** Senders oldest first, your replies as [me], at most three names. */
internal fun conversationSenders(row: InboxRow, me: String): String {
    val timeline = (row.members.map { it to false } + row.sent.map { it to true }).sortedBy { it.first.atUtc.orEmpty() }
    val names = timeline.map { (email, mine) -> if (mine) me else senderName(email.sender) }.distinct()
    return if (names.size > 3) names.take(3).joinToString(", ") + "…" else names.joinToString(", ")
}

/** The display name of a `Name <address>` sender, else the address. */
internal fun senderName(sender: String): String {
    val name = sender.substringBefore('<').trim().trim('"')
    return name.ifBlank { sender.substringAfter('<').substringBefore('>').trim() }.ifBlank { sender }
}
