package org.kysecurity.mail

import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ReplyThreadHandoffTest {

    @After
    fun reset() = ReplyThreadHandoff.resetForNewSession()

    @Test
    fun aTokenYieldsItsReplyOnce() {
        val token = ReplyThreadHandoff.put(ReplyRef("42", "Archive"))

        assertEquals(ReplyRef("42", "Archive"), ReplyThreadHandoff.take(token))
        assertNull(ReplyThreadHandoff.take(token))
    }

    /** Compose is exported: a token another app invents, or none, names no message. */
    @Test
    fun anUnknownOrMissingTokenYieldsNothing() {
        ReplyThreadHandoff.put(ReplyRef("42", "INBOX"))

        assertNull(ReplyThreadHandoff.take("42"))
        assertNull(ReplyThreadHandoff.take(null))
    }

    @Test
    fun aSessionResetDropsPendingReplies() {
        val token = ReplyThreadHandoff.put(ReplyRef("42", "INBOX"))

        ReplyThreadHandoff.resetForNewSession()

        assertNull(ReplyThreadHandoff.take(token))
    }
}
