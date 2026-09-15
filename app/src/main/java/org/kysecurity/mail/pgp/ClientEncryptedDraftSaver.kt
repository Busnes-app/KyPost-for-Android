package org.kysecurity.mail.pgp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.kysecurity.mail.mail.ClientEncryptedDraft
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import java.time.OffsetDateTime
import java.time.ZoneOffset
import kotlin.coroutines.coroutineContext

internal sealed class DraftSaveOutcome {
    object Saved : DraftSaveOutcome()
    object Cancelled : DraftSaveOutcome()
    object NotEnrolled : DraftSaveOutcome()
    object NoSecureLockScreen : DraftSaveOutcome()
    object NoAccountAddress : DraftSaveOutcome()
    object NoRecipient : DraftSaveOutcome()
    object EncryptFailed : DraftSaveOutcome()
    object UnsealFailed : DraftSaveOutcome()
    data class SaveFailed(val outcome: MailOutcome<*>) : DraftSaveOutcome()
}

/** A draft needs only the author's vault key; recipient discovery has no role here. */
internal class ClientEncryptedDraftSaver(
    private val opener: VaultOpener,
    private val accountAddress: String,
    private val transport: (ClientEncryptedDraft) -> MailOutcome<Unit>,
) {
    suspend fun save(draft: MailDraft): DraftSaveOutcome {
        val from = accountAddress.trim()
        if (from.isEmpty()) return DraftSaveOutcome.NoAccountAddress
        val fields = splitRecipientFields(draft.to, draft.cc, draft.bcc)
        if (fields.to.isEmpty()) return DraftSaveOutcome.NoRecipient
        if (!EnrollmentSession.isHeld()) {
            val opened = try {
                opener.open()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                return DraftSaveOutcome.UnsealFailed
            }
            when (opened) {
                OpenOutcome.Opened -> Unit
                OpenOutcome.Cancelled -> return DraftSaveOutcome.Cancelled
                OpenOutcome.NotEnrolled -> return DraftSaveOutcome.NotEnrolled
                OpenOutcome.NoSecureLockScreen -> return DraftSaveOutcome.NoSecureLockScreen
                is OpenOutcome.Failed -> return DraftSaveOutcome.UnsealFailed
            }
        }
        val encrypted = withContext(Dispatchers.Default) {
            EnrollmentSession.withSigner { signer ->
                val ownKey = signer?.let { PgpEncryptor.ownPublicKey(it) } ?: return@withSigner null
                val content = buildProtectedContent(
                    contentType = if (draft.mode.equals("plain", true)) "text/plain; charset=utf-8" else "text/html; charset=utf-8",
                    body = draft.body, subject = draft.subject,
                    to = fields.to, cc = fields.cc, bcc = fields.bcc,
                    attachments = draft.attachments.map { OutgoingMimeAttachment(it.name, it.mimeType, it.bytes) },
                ).toByteArray(Charsets.UTF_8)
                try {
                    val result = PgpEncryptor.encrypt(content, listOf(ownKey), signer)
                    if (result !is EncryptResult.Ok) return@withSigner null
                    ClientEncryptedDraft(
                        fields.to.joinToString(", "),
                        wrapAsPgpMime(
                            OutgoingEnvelope(from, fields.to, emptyList(), rfc5322Date(OffsetDateTime.now(ZoneOffset.UTC))),
                            result.armored,
                        ),
                    )
                } finally {
                    content.fill(0)
                }
            }
        } ?: return if (EnrollmentSession.isHeld()) DraftSaveOutcome.EncryptFailed else DraftSaveOutcome.NotEnrolled
        coroutineContext.ensureActive()
        val saved = try {
            withContext(Dispatchers.IO) { transport(encrypted) }
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            MailOutcome.UpstreamFailure("Could not save encrypted draft")
        }
        return when (val outcome = saved) {
            is MailOutcome.Success -> DraftSaveOutcome.Saved
            else -> DraftSaveOutcome.SaveFailed(outcome)
        }
    }
}
