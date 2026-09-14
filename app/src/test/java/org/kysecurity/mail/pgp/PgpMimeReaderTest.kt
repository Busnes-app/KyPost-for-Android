package org.kysecurity.mail.pgp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class PgpMimeReaderTest {

    private fun read(mime: String) = PgpMimeReader.read(mime.toByteArray(Charsets.UTF_8))

    private val pngBase64 = java.util.Base64.getEncoder().encodeToString(byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47))

    @Test
    fun collectsAnAttachmentPartBesideTheBody() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            see attached
            --b1
            Content-Type: application/pdf; name="report.pdf"
            Content-Disposition: attachment; filename="report.pdf"
            Content-Transfer-Encoding: base64

            JVBERi0xLjQK
            --b1--
            """.trimIndent(),
        )

        assertEquals("see attached", body?.plain?.trim())
        val attachment = body!!.attachments.single()
        assertEquals("report.pdf", attachment.name)
        assertEquals("application/pdf", attachment.mimeType)
        assertEquals("%PDF-1.4\n", String(attachment.bytes, Charsets.ISO_8859_1))
        assertNull(attachment.contentId)
        assertTrue(!body.attachmentsOmitted)
    }

    @Test
    fun aTextPartWithAnAttachmentDispositionIsAnAttachmentNotTheBody() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            the body
            --b1
            Content-Type: text/plain; charset=utf-8; name="notes.txt"
            Content-Disposition: attachment; filename="notes.txt"

            not the body
            --b1--
            """.trimIndent(),
        )

        assertEquals("the body", body?.plain?.trim())
        assertEquals("notes.txt", body?.attachments?.single()?.name)
    }

    @Test
    fun anInlineImageCarriesItsContentIdWithoutTheAngleBrackets() {
        val body = read(
            """
            Content-Type: multipart/related; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            <img src="cid:logo@kypost">
            --b1
            Content-Type: image/png; name="logo.png"
            Content-Disposition: inline; filename="logo.png"
            Content-ID: <logo@kypost>
            Content-Transfer-Encoding: base64

            $pngBase64
            --b1--
            """.trimIndent(),
        )

        assertEquals("logo@kypost", body?.attachments?.single()?.contentId)
        assertEquals("image/png", body?.attachments?.single()?.mimeType)
    }

    @Test
    fun attachmentsPastTheByteCapAreDroppedWholeAndReported() {
        val big = "A".repeat(PgpMimeReader.attachmentByteCap.toInt() + 1)
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            body
            --b1
            Content-Type: application/octet-stream; name="huge.bin"
            Content-Disposition: attachment; filename="huge.bin"

            $big
            --b1
            Content-Type: application/octet-stream; name="small.bin"
            Content-Disposition: attachment; filename="small.bin"

            tiny
            --b1--
            """.trimIndent(),
        )

        // The oversize part is gone entirely: a truncated file is worse than a missing one.
        assertEquals(listOf("small.bin"), body?.attachments?.map { it.name })
        assertTrue("the reader must say a part was dropped", body!!.attachmentsOmitted)
    }

    @Test
    fun attachmentsPastThePartCapAreDroppedAndReported() {
        val parts = (1..PgpMimeReader.MAX_ATTACHMENT_PARTS + 1).joinToString("\n") { i ->
            """
            --b1
            Content-Type: application/octet-stream; name="f$i.bin"
            Content-Disposition: attachment; filename="f$i.bin"

            x
            """.trimIndent()
        }
        val body = read("Content-Type: multipart/mixed; boundary=\"b1\"\n\n$parts\n--b1--")

        assertEquals(PgpMimeReader.MAX_ATTACHMENT_PARTS, body?.attachments?.size)
        assertTrue(body!!.attachmentsOmitted)
    }

    @Test
    fun anAttachmentOnlyMessageStillReadsAsAMessage() {
        // No body part at all. Today read() returns null when html and plain are both null; an
        // attachment is content, so it must not.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: application/pdf; name="only.pdf"
            Content-Disposition: attachment; filename="only.pdf"

            x
            --b1--
            """.trimIndent(),
        )

        assertEquals("only.pdf", body?.attachments?.single()?.name)
        assertEquals("plain", body?.bodyMode)
        assertEquals("", body?.plain)
    }

    @Test
    fun aContentIdOnTheHtmlBodyDoesNotTurnItIntoAnAttachment() {
        // Many mailers stamp a Content-ID on every part, including the body. Only disposition
        // decides; the body must survive alongside the real inline attachment.
        val body = read(
            """
            Content-Type: multipart/related; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8
            Content-ID: <body@x>

            <p>hello</p><img src="cid:logo@kypost">
            --b1
            Content-Type: image/png; name="logo.png"
            Content-Disposition: inline; filename="logo.png"
            Content-ID: <logo@kypost>
            Content-Transfer-Encoding: base64

            $pngBase64
            --b1--
            """.trimIndent(),
        )

        assertEquals("<p>hello</p><img src=\"cid:logo@kypost\">", body?.html?.trim())
        assertEquals("logo@kypost", body?.attachments?.single()?.contentId)
    }

    @Test
    fun aNamedTextPartWithNoDispositionIsTheBodyNotAnAttachment() {
        // Outlook lineage: a body text/plain part can carry name= with no Content-Disposition at
        // all. name= alone must never make a text part a file.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8; name="message.txt"

            the body
            --b1--
            """.trimIndent(),
        )

        assertEquals("the body", body?.plain?.trim())
        assertTrue(body!!.attachments.isEmpty())
    }

    @Test
    fun attachmentsPastTheCumulativeByteCapAreDropped() {
        val chunk = "A".repeat((PgpMimeReader.attachmentByteCap / 2 + 1).toInt())
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            body
            --b1
            Content-Type: application/octet-stream; name="one.bin"
            Content-Disposition: attachment; filename="one.bin"

            $chunk
            --b1
            Content-Type: application/octet-stream; name="two.bin"
            Content-Disposition: attachment; filename="two.bin"

            $chunk
            --b1
            Content-Type: application/octet-stream; name="three.bin"
            Content-Disposition: attachment; filename="three.bin"

            $chunk
            --b1--
            """.trimIndent(),
        )

        assertEquals(listOf("one.bin"), body?.attachments?.map { it.name })
        assertTrue(body!!.attachmentsOmitted)
    }

    @Test
    fun readsAPlainTextOnlyMessage() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8

            Just text.
            """.trimIndent(),
        )

        assertEquals("Just text.", body?.plain?.trim())
        assertNull(body?.html)
    }

    @Test
    fun prefersHtmlFromMultipartAlternative() {
        val body = read(
            """
            Content-Type: multipart/alternative; boundary="b1"

            --b1
            Content-Type: text/plain; charset=utf-8

            fallback text
            --b1
            Content-Type: text/html; charset=utf-8

            <p>rich text</p>
            --b1--
            """.trimIndent(),
        )

        assertTrue("expected the html part", body?.html?.contains("rich text") == true)
        assertTrue("expected the plain part kept too", body?.plain?.contains("fallback text") == true)
    }

    @Test
    fun recoversAProtectedSubject() {
        val body = read(
            """
            Content-Type: text/plain; charset=utf-8
            Subject: The real subject

            body
            """.trimIndent(),
        )

        assertEquals("The real subject", body?.protectedSubject)
    }

    @Test
    fun returnsNullForBytesThatAreNotMime() {
        // Fails closed: the caller shows "could not decrypt" rather than rendering garbage
        // into a WebView.
        assertNull(PgpMimeReader.read(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun distinguishesAGenuinelyEmptyBodyFromGarbage() {
        // An explicit Content-Type header was parsed here, so the empty body is real content (e.g. an
        // "attachment only, no body" compose) — not the RFC 2045 default angus.mail falls back to for
        // non-MIME input. It must not be collapsed to null like the garbage-bytes case below.
        val mime = "Content-Type: text/plain; charset=utf-8\n\n"

        val body = PgpMimeReader.read(mime.toByteArray(Charsets.UTF_8))

        assertEquals("", body?.plain)
        assertNull(body?.html)
        assertNull(PgpMimeReader.read(byteArrayOf(0x00, 0x01, 0x02)))
    }

    @Test
    fun recursesIntoNestedMultiparts() {
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="outer"

            --outer
            Content-Type: multipart/alternative; boundary="inner"

            --inner
            Content-Type: text/plain; charset=utf-8

            nested fallback text
            --inner
            Content-Type: text/html; charset=utf-8

            <p>nested rich text</p>
            --inner--
            --outer--
            """.trimIndent(),
        )

        assertTrue("expected the nested html part", body?.html?.contains("nested rich text") == true)
        assertTrue("expected the nested plain part", body?.plain?.contains("nested fallback text") == true)
    }

    @Test
    fun walkPrefersFirstNonBlankPartOverAnEarlierBlankSibling() {
        // A blank part must not lock the slot: if a later sibling of the same subtype carries real
        // content, that content has to win. Otherwise it is silently dropped and the message renders
        // blank with no error shown to the user.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            --b1
            Content-Type: text/html; charset=utf-8

            <p>real content</p>
            --b1--
            """.trimIndent(),
        )

        assertEquals("<p>real content</p>", body?.html?.trim())
    }

    @Test
    fun walkKeepsRealContentWhenALaterSiblingOfTheSameSubtypeIsBlank() {
        // Once the slot holds real content, a later blank sibling must not overwrite it.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            <p>real content</p>
            --b1
            Content-Type: text/html; charset=utf-8

            --b1--
            """.trimIndent(),
        )

        assertEquals("<p>real content</p>", body?.html?.trim())
    }

    @Test
    fun walkKeepsAnAllBlankMultipartAsEmptyStringNotNull() {
        // A blank part is still real content when nothing better ever turns up.
        val body = read(
            """
            Content-Type: multipart/mixed; boundary="b1"

            --b1
            Content-Type: text/html; charset=utf-8

            --b1--
            """.trimIndent(),
        )

        assertEquals("", body?.html)
        assertNull(body?.plain)
    }
}
