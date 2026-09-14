package org.kysecurity.mail.pgp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.*
import org.junit.Test
import org.kysecurity.mail.mail.ClientEncryptedDraft
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.OutgoingAttachment

class ClientEncryptedDraftSaverTest {
    @After fun clearSession() = EnrollmentSession.clear()

    private val draft = MailDraft(
        to = "alice@example.invalid", cc = "cc@example.invalid", bcc = "hidden@example.invalid",
        subject = "private subject", body = "private body", mode = "plain",
        attachments = listOf(OutgoingAttachment("note.txt", "text/plain", byteArrayOf(1, 2, 3))),
    )

    @Test fun draftIsSignedToOwnKeyWithAllFieldsProtected() = runBlocking {
        var saved: ClientEncryptedDraft? = null
        val result = ClientEncryptedDraftSaver(FakeVaultOpener(), "me@example.invalid") {
            saved = it
            MailOutcome.Success(Unit)
        }.save(draft)
        assertEquals(DraftSaveOutcome.Saved, result)
        val wire = saved!!
        assertEquals(draft.to, wire.to)
        val headers = wire.pgpDraft.substringBefore("\r\n\r\n")
        assertTrue(headers.contains("Subject: $OUTER_PLACEHOLDER_SUBJECT"))
        for (secret in listOf(draft.cc, draft.bcc, draft.subject, draft.body, "note.txt")) {
            assertFalse("plaintext leaked: $secret", wire.pgpDraft.contains(secret))
        }
        val decrypted = PgpDecryptor.decrypt(
            TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray(), armorOf(wire.pgpDraft),
            listOf(TestPgpPrivateKey.ARMORED_PUBLIC),
        ) as DecryptResult.Ok
        try {
            assertTrue(decrypted.signature.valid)
            val text = decrypted.plaintext.toString(Charsets.UTF_8)
            for (header in listOf("To: ${draft.to}", "Cc: ${draft.cc}", "Bcc: ${draft.bcc}", "Subject: ${draft.subject}")) {
                assertTrue(text.contains(header))
            }
            val body = PgpMimeReader.read(decrypted.plaintext)!!
            assertTrue(body.plain.orEmpty().contains(draft.body))
            assertArrayEquals(draft.attachments.single().bytes, body.attachments.single { it.name == "note.txt" }.bytes)
        } finally { decrypted.plaintext.fill(0) }
        assertTrue(PgpDecryptor.decrypt(TestPgpSecondKey.ARMORED_PRIVATE.toCharArray(), armorOf(wire.pgpDraft), emptyList()) is DecryptResult.Failed)
    }

    @Test fun recipientHeadersExistWithEmptySubjectAndCannotInjectHeaders() {
        val content = buildProtectedContent(
            "text/plain", "body", "", to = listOf("to@example.invalid\r\nInjected: no"),
            cc = listOf("cc@example.invalid"), bcc = listOf("hidden@example.invalid"),
        )
        assertTrue(content.contains("Content-Type: text/rfc822-headers"))
        assertTrue(content.contains("To: to@example.invalid Injected: no"))
        assertFalse(content.contains("\r\nInjected:"))
        assertTrue(content.contains("Bcc: hidden@example.invalid"))
    }

    @Test fun refusedUnlocksNeverUpload() = runBlocking {
        for ((open, expected) in listOf(
            OpenOutcome.Cancelled to DraftSaveOutcome.Cancelled,
            OpenOutcome.NotEnrolled to DraftSaveOutcome.NotEnrolled,
            OpenOutcome.NoSecureLockScreen to DraftSaveOutcome.NoSecureLockScreen,
            OpenOutcome.Failed("unavailable") to DraftSaveOutcome.UnsealFailed,
        )) {
            val saver = ClientEncryptedDraftSaver(FakeVaultOpener(outcome = open), "me@example.invalid") {
                error("must not upload")
            }
            assertEquals(expected, saver.save(draft))
        }
    }

    @Test fun missingAddressOrRecipientDoesNotPromptOrUpload() = runBlocking {
        val opener = object : VaultOpener { override suspend fun open(): OpenOutcome = error("must not prompt") }
        assertEquals(DraftSaveOutcome.NoAccountAddress, ClientEncryptedDraftSaver(opener, " ") { error("upload") }.save(draft))
        assertEquals(DraftSaveOutcome.NoRecipient, ClientEncryptedDraftSaver(opener, "me@example.invalid") { error("upload") }.save(draft.copy(to = " , ")))
    }

    @Test fun lostSessionAndInvalidKeyNeverUpload() = runBlocking {
        val opener = object : VaultOpener { override suspend fun open() = OpenOutcome.Opened }
        val saver = ClientEncryptedDraftSaver(opener, "me@example.invalid") { error("must not upload") }
        assertEquals(DraftSaveOutcome.NotEnrolled, saver.save(draft))
        EnrollmentSession.put("invalid".toCharArray())
        assertEquals(DraftSaveOutcome.EncryptFailed, saver.save(draft))
    }

    @Test fun transportFailurePreservesDraftAndDoesNotRetry() = runBlocking {
        var calls = 0
        val failure = MailOutcome.UpstreamFailure("offline")
        val result = ClientEncryptedDraftSaver(FakeVaultOpener(), "me@example.invalid") {
            calls++
            failure
        }.save(draft)
        assertEquals(DraftSaveOutcome.SaveFailed(failure), result)
        assertEquals(1, calls)
        assertArrayEquals(byteArrayOf(1, 2, 3), draft.attachments.single().bytes)
    }

    @Test fun unexpectedUnlockAndTransportFailuresStayRecoverable() = runBlocking {
        val opener = object : VaultOpener { override suspend fun open(): OpenOutcome = error("storage unavailable") }
        assertEquals(DraftSaveOutcome.UnsealFailed,
            ClientEncryptedDraftSaver(opener, "me@example.invalid") { error("upload") }.save(draft))
        assertTrue(ClientEncryptedDraftSaver(FakeVaultOpener(), "me@example.invalid") {
            throw java.io.IOException("offline")
        }.save(draft) is DraftSaveOutcome.SaveFailed)
    }

    @Test fun heldKeyNeedsNoNewPrompt() = runBlocking {
        EnrollmentSession.put(TestPgpPrivateKey.ARMORED_PRIVATE.toCharArray())
        val opener = object : VaultOpener { override suspend fun open(): OpenOutcome = error("already unlocked") }
        assertEquals(DraftSaveOutcome.Saved,
            ClientEncryptedDraftSaver(opener, "me@example.invalid") { MailOutcome.Success(Unit) }.save(draft))
    }

    @Test fun cancellationPropagatesWithoutUpload() = runBlocking {
        val opener = object : VaultOpener { override suspend fun open(): OpenOutcome = throw CancellationException() }
        try {
            ClientEncryptedDraftSaver(opener, "me@example.invalid") { error("upload") }.save(draft)
            fail("cancellation swallowed")
        } catch (_: CancellationException) { }
    }
}
