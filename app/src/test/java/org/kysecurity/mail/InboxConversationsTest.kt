package org.kysecurity.mail

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.kysecurity.mail.mail.Conversation
import org.kysecurity.mail.mail.MailAccount

class InboxConversationsTest {

    private fun email(id: String, at: String, sender: String = "Ana <ana@example.invalid>", status: String = "read", folder: String = "INBOX") =
        Email(id = id, subject = "s$id", sender = sender, preview = "", atUtc = at, status = status, folder = folder)

    private val a1 = email("1", "2026-11-01T08:00:00Z")
    private val b2 = email("2", "2026-11-01T09:00:00Z", sender = "Bo <bo@example.invalid>")
    private val a3 = email("3", "2026-11-01T10:00:00Z", status = "unread")
    private val newestFirst = listOf(a3, b2, a1)
    private val thread = Conversation("1", listOf("1", "3"))

    @Test
    fun withoutConversations_everyMessageIsItsOwnRow() {
        val rows = groupInboxRows(newestFirst, newestFirst, emptyList(), emptySet())

        assertEquals(newestFirst, rows.map { it.email })
        assertTrue(rows.none { it.isConversation })
    }

    @Test
    fun aConversationStandsAtItsNewestShownMember_andCoversEveryMember() {
        val rows = groupInboxRows(newestFirst, newestFirst, listOf(thread), emptySet())

        assertEquals(listOf("3", "2"), rows.map { it.email.id })
        val conversation = rows.first()
        assertTrue(conversation.isConversation)
        assertEquals("oldest first", listOf(a1, a3), conversation.members)
        assertTrue("unread when any member is", conversation.unread)
        assertFalse(rows[1].isConversation)
    }

    /** A keyword tab shows only some rows; an action on the conversation still covers the folder. */
    @Test
    fun membersComeFromTheFolder_notOnlyTheShownTab() {
        val rows = groupInboxRows(listOf(a1), newestFirst, listOf(thread), emptySet())

        assertEquals(listOf(a1, a3), rows.single().members)
    }

    @Test
    fun aGroupWithOneLoadedMessageAndNoReplies_isAPlainRow() {
        val rows = groupInboxRows(listOf(a3), listOf(a3), listOf(thread), emptySet())

        assertFalse(rows.single().isConversation)
        assertEquals(listOf(a3), rows.single().members)
    }

    @Test
    fun aMessageAndYourReply_isAConversationOfTwo_thatActsOnlyOnThisFolder() {
        val reply = email("9", "2026-11-01T11:00:00Z", folder = "Sent")
        val rows = groupInboxRows(listOf(a1), listOf(a1), listOf(Conversation("1", listOf("1"), listOf(reply))), emptySet())

        val row = rows.single()
        assertTrue(row.isConversation)
        assertEquals(2, row.count)
        assertEquals(listOf(a1), row.members)
    }

    @Test
    fun anExpandedConversation_isFollowedByItsMessagesOldestFirst_repliesIncluded() {
        val reply = email("9", "2026-11-01T09:30:00Z", folder = "Sent")
        val rows = groupInboxRows(newestFirst, newestFirst, listOf(thread.copy(sent = listOf(reply))), setOf("1"))

        assertEquals(listOf("3", "1", "9", "3", "2"), rows.map { it.email.id })
        assertTrue(rows[0].expanded)
        assertEquals(listOf(false, true, true, true, false), rows.map { it.nested })
        assertEquals("keys stay unique for DiffUtil", rows.size, rows.map { it.key }.toSet().size)
    }

    @Test
    fun senders_areOldestFirst_unique_withYourRepliesAsMe() {
        val reply = email("9", "2026-11-01T09:30:00Z", sender = "me@example.invalid", folder = "Sent")
        val row = groupInboxRows(newestFirst, newestFirst, listOf(Conversation("1", listOf("1", "2", "3"), listOf(reply))), emptySet()).single()

        assertEquals("Ana, Bo, me", conversationSenders(row, "me"))
    }

    @Test
    fun senders_stopAtThree() {
        val people = (1..4).map { email("$it", "2026-11-01T0$it:00:00Z", sender = "P$it <p$it@example.invalid>") }
        val row = groupInboxRows(people.reversed(), people, listOf(Conversation("1", people.map { it.id })), emptySet()).single()

        assertEquals("P1, P2, P3…", conversationSenders(row, "me"))
    }

    @Test
    fun senderName_fallsBackToTheAddress() {
        assertEquals("Ana", senderName("\"Ana\" <ana@example.invalid>"))
        assertEquals("ana@example.invalid", senderName("<ana@example.invalid>"))
        assertEquals("ana@example.invalid", senderName("ana@example.invalid"))
    }

    /** A refresh brings a newer reply, so the selected conversation has a new lead. The selection
     *  follows it: the row stays selected and an action still finds every member. */
    @Test
    fun aSelectedConversation_followsItsNewLead() {
        val a4 = email("4", "2026-11-01T11:00:00Z")
        val refreshed = listOf(a4, a3, b2, a1)
        val rows = groupInboxRows(refreshed, refreshed, listOf(Conversation("1", listOf("1", "3", "4"))), emptySet())

        assertEquals(setOf("4", "2"), followLeads(setOf("3", "2"), rows))
        assertEquals("unknown ids are kept", setOf("9"), followLeads(setOf("9"), rows))
    }

    private val first = MailAccount("sub-1", "https://one.example.invalid")
    private val second = MailAccount("sub-2", "https://two.example.invalid")
    private val reply = email("90", "2026-11-01T12:00:00Z", sender = "Me <me@one.example.invalid>", folder = "Sent")

    /** Another account's message ids can repeat this one's; its Sent replies must not attach. */
    @Test
    fun conversationCache_isClearedWhenTheAccountChanges() {
        val cache = ConversationCache()
        assertTrue(cache.put(first, session = 1, current = 1, "INBOX", listOf(Conversation("1", listOf("1", "3"), listOf(reply)))))

        assertEquals(1, cache.get(first, current = 1, "INBOX").size)
        assertEquals("a new account starts with no grouping", emptyList<Conversation>(), cache.get(second, current = 1, "INBOX"))
        assertEquals("and the old one's is gone, not set aside", emptyList<Conversation>(), cache.get(first, current = 1, "INBOX"))
    }

    @Test
    fun conversationCache_isClearedWhenTheSessionEnds() {
        val cache = ConversationCache()
        cache.put(first, session = 1, current = 1, "INBOX", listOf(thread))

        assertEquals(emptyList<Conversation>(), cache.get(first, current = 2, "INBOX"))
    }

    /** A fetch started before the session ended answers for the old account: it is dropped. */
    @Test
    fun conversationCache_dropsAnAnswerFromAnEndedSession() {
        val cache = ConversationCache()

        assertFalse(cache.put(second, session = 1, current = 2, "INBOX", listOf(Conversation("1", listOf("1", "3"), listOf(reply)))))
        assertEquals(emptyList<Conversation>(), cache.get(second, current = 2, "INBOX"))
    }

    /** New mail is shown before the conversations request, however long that one takes. */
    @Test
    fun aRefreshPaintsTheMailBeforeAskingForItsGrouping() {
        val events = mutableListOf<String>()
        paintThenGroup(
            paint = { events += "paint" },
            group = { events += "group"; listOf(thread) },
            regroup = { events += "regroup" },
        )

        assertEquals(listOf("paint", "group", "regroup"), events)
    }

    @Test
    fun noGrouping_leavesThePaintAlone() {
        val events = mutableListOf<String>()
        paintThenGroup<List<Conversation>>(paint = { events += "paint" }, group = { null }, regroup = { events += "regroup" })

        assertEquals(listOf("paint"), events)
    }
}
