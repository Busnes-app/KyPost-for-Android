package org.kysecurity.mail

import org.junit.After
import org.junit.Before
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.kysecurity.mail.mail.OutgoingAttachment

class ComposeDraftCacheTest {

    /** The cache is process-wide, so arrive clean rather than trusting whoever ran before: any
     *  other class calling `InMemoryPlaintext.clearAll()` leaves it sealed, which makes `save()`
     *  here a silent no-op. */
    @Before
    fun unseal() {
        ComposeDraftCache.take()
    }

    /** The cache is process-wide: clear() seals it, and only take() unseals for the next test. */
    @After
    fun tearDown() {
        ComposeDraftCache.clear()
        ComposeDraftCache.take()
    }

    @Test
    fun takeReturnsTheSavedDraftAndClearsIt() {
        ComposeDraftCache.save(draft(subject = "Hello"))

        assertEquals("Hello", ComposeDraftCache.take()?.subject)
        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun anEmptyDraftIsNotWorthKeeping() {
        ComposeDraftCache.save(draft())

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun aTypedFieldOtherThanSubjectIsWorthKeeping() {
        ComposeDraftCache.save(draft(bodyHtml = "<p>hi</p>"))

        assertEquals("<p>hi</p>", ComposeDraftCache.take()?.bodyHtml)
    }

    @Test
    fun anAttachmentAloneIsWorthKeeping() {
        ComposeDraftCache.save(
            draft(attachments = listOf(OutgoingAttachment("photo.jpg", "image/jpeg", ByteArray(1024)))),
        )

        assertEquals("photo.jpg", ComposeDraftCache.take()?.attachments?.single()?.name)
    }

    @Test
    fun clearSealsAgainstALateWrite() {
        ComposeDraftCache.clear()

        ComposeDraftCache.save(draft(subject = "Late Arrival"))

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun takeUnsealsForTheNextSession() {
        ComposeDraftCache.clear()
        ComposeDraftCache.take()

        ComposeDraftCache.save(draft(subject = "Grace Hopper"))

        assertEquals("Grace Hopper", ComposeDraftCache.take()?.subject)
    }

    @Test
    fun resetForNewSessionDropsEverything() {
        ComposeDraftCache.save(draft(subject = "Ada Lovelace"))

        ComposeDraftCache.resetForNewSession()

        assertNull(ComposeDraftCache.take())
    }

    @Test
    fun aRecreatedScreenTakesItsOwnDraftBackWhateverItsIntent() {
        ComposeDraftCache.save(draft(subject = "Shared notes"))

        assertEquals("Shared notes", ComposeDraftCache.takeOnOpen(newExternalRequest = false)?.subject)
    }

    @Test
    fun aNewExternalRequestDropsAndZeroesTheCachedDraftButStaysUnsealed() {
        val bytes = byteArrayOf(1, 2, 3)
        ComposeDraftCache.save(draft(attachments = listOf(OutgoingAttachment("a.bin", "application/octet-stream", bytes))))

        assertNull(ComposeDraftCache.takeOnOpen(newExternalRequest = true))
        assertArrayEquals(ByteArray(3), bytes)
        ComposeDraftCache.save(draft(subject = "New"))
        assertEquals("New", ComposeDraftCache.take()?.subject)
    }

    private fun draft(
        to: String = "",
        cc: String = "",
        bcc: String = "",
        subject: String = "",
        bodyHtml: String = "",
        attachments: List<OutgoingAttachment> = emptyList(),
    ) = CachedDraft(to = to, cc = cc, bcc = bcc, subject = subject, bodyHtml = bodyHtml, attachments = attachments)
}
