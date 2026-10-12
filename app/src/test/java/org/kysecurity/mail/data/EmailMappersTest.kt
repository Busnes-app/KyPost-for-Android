package org.kysecurity.mail.data

import org.kysecurity.mail.Email
import org.junit.Assert.assertEquals
import org.junit.Test

class EmailMappersTest {

    @Test
    fun toEntity_toUiEmail_roundTripsAllFields() {
        val email = Email(
            id = "msg-1",
            subject = "Subject",
            sender = "sender@example.com",
            preview = "Preview text",
            keywords = setOf("Work", "Urgent"),
            sentTo = "me@example.com",
            cc = "cc@example.com",
            bcc = "bcc@example.com",
            body = "<p>Body</p>",
            bodyMode = "html",
            label = "Work",
            status = "read",
            atUtc = "2026-07-07T20:43:25Z",
            wokenAt = "2026-07-08T09:00:00Z",
            sourceMode = "relay",
        )

        val entity = email.toEntity(folder = "INBOX", sourceMode = "relay")
        val roundTripped = entity.toUiEmail()

        assertEquals(email.id, roundTripped.id)
        assertEquals(email.subject, roundTripped.subject)
        assertEquals(email.sender, roundTripped.sender)
        assertEquals(email.keywords, roundTripped.keywords)
        assertEquals(email.sentTo, roundTripped.sentTo)
        assertEquals(email.cc, roundTripped.cc)
        assertEquals(email.bcc, roundTripped.bcc)
        assertEquals(email.body, roundTripped.body)
        assertEquals(email.bodyMode, roundTripped.bodyMode)
        assertEquals(email.label, roundTripped.label)
        assertEquals(email.status, roundTripped.status)
        assertEquals(email.atUtc, roundTripped.atUtc)
        assertEquals(email.wokenAt, roundTripped.wokenAt)
        assertEquals("INBOX", entity.folder)
    }

    @Test
    fun toEntity_emptyKeywords_encodesAsEmptyJsonArray() {
        val email = Email(id = "msg-2", subject = "S", sender = "s@example.com", preview = "P")

        val entity = email.toEntity(folder = "INBOX", sourceMode = "imap")

        assertEquals("[]", entity.keywordsJson)
    }
}
