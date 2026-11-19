package org.kysecurity.mail

import org.kysecurity.mail.mail.Conversation
import org.kysecurity.mail.mail.MailAccount

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

/** A selection holds lead ids. When a refresh gives a conversation a newer lead, a selected
 *  member's id becomes the new lead's, so the row stays selected and an action covers it all. */
internal fun followLeads(selected: Set<String>, rows: List<InboxRow>): Set<String> {
    if (selected.isEmpty()) return selected
    val leadOf = HashMap<String, String>()
    rows.filter { it.isConversation }.forEach { row -> row.members.forEach { leadOf[it.id] = row.email.id } }
    return selected.mapTo(LinkedHashSet()) { leadOf[it] ?: it }
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

/** The server's groupings, per folder, for one account in one session: another account's message
 *  ids can repeat this one's, and its Sent replies must never attach to them. Main thread only. */
internal class ConversationCache {
    private var owner: Pair<MailAccount?, Long>? = null
    private val byFolder = mutableMapOf<String, List<Conversation>>()

    /** False, keeping nothing, when the session the fetch started under ([session]) has ended. */
    fun put(account: MailAccount?, session: Long, current: Long, folder: String, conversations: List<Conversation>): Boolean {
        if (session != current) return false
        ownedBy(account, session)
        byFolder[folder] = conversations
        return true
    }

    fun get(account: MailAccount?, current: Long, folder: String): List<Conversation> {
        ownedBy(account, current)
        return byFolder[folder].orEmpty()
    }

    private fun ownedBy(account: MailAccount?, session: Long) {
        if (owner == account to session) return
        owner = account to session
        byFolder.clear()
    }
}
