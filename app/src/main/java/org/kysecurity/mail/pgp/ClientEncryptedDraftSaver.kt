package org.kysecurity.mail.pgp

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.kysecurity.mail.mail.ClientEncryptedDraft
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import java.time.OffsetDateTime
import java.time.ZoneOffset
import kotlin.coroutines.coroutineContext

internal sealed class DraftEncryption {
    class Ok(val draft: ClientEncryptedDraft) : DraftEncryption()
    class Refused(val outcome: DraftSaveOutcome) : DraftEncryption()
}

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
        val encrypted = when (val result = encrypt(draft, OffsetDateTime.now(ZoneOffset.UTC))) {
            is DraftEncryption.Ok -> result.draft
            is DraftEncryption.Refused -> return result.outcome
        }
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

    /** Opens the vault if it is not held, then encrypts [draft] for Drafts, dated [date]. Sends
     *  nothing: a scheduled send carries the result as its fallback copy. */
    suspend fun encrypt(draft: MailDraft, date: OffsetDateTime): DraftEncryption {
        val from = accountAddress.trim()
        if (from.isEmpty()) return DraftEncryption.Refused(DraftSaveOutcome.NoAccountAddress)
        val fields = splitRecipientFields(draft.to, draft.cc, draft.bcc)
        if (fields.to.isEmpty()) return DraftEncryption.Refused(DraftSaveOutcome.NoRecipient)
        if (!EnrollmentSession.isHeld()) {
            val opened = try {
                opener.open()
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                return DraftEncryption.Refused(DraftSaveOutcome.UnsealFailed)
            }
            when (opened) {
                OpenOutcome.Opened -> Unit
                OpenOutcome.Cancelled -> return DraftEncryption.Refused(DraftSaveOutcome.Cancelled)
                OpenOutcome.NotEnrolled -> return DraftEncryption.Refused(DraftSaveOutcome.NotEnrolled)
                OpenOutcome.NoSecureLockScreen -> return DraftEncryption.Refused(DraftSaveOutcome.NoSecureLockScreen)
                is OpenOutcome.Failed -> return DraftEncryption.Refused(DraftSaveOutcome.UnsealFailed)
            }
        }
        val encrypted = withContext(Dispatchers.Default) {
            EnrollmentSession.withSigner { signer ->
                signer ?: return@withSigner null
                val copy = encryptDraftCopy(signer, draft, fields, from, rfc5322Date(date))
                copy?.let { ClientEncryptedDraft(fields.to.joinToString(", "), it) }
            }
        } ?: return DraftEncryption.Refused(
            if (EnrollmentSession.isHeld()) DraftSaveOutcome.EncryptFailed else DraftSaveOutcome.NotEnrolled,
        )
        return DraftEncryption.Ok(encrypted)
    }
}

/** [draft] as Drafts holds it: encrypted to the account's own key only, signed, and with its
 *  recipients in the protected headers, since the envelope names only To. Null when the own key
 *  cannot be derived or encryption fails. */
internal fun encryptDraftCopy(
    signer: PGPSecretKeyRing,
    draft: MailDraft,
    fields: RecipientFields,
    from: String,
    date: String,
): String? {
    val ownKey = PgpEncryptor.ownPublicKey(signer) ?: return null
    val content = buildProtectedContent(
        contentType = if (draft.mode.equals("plain", true)) "text/plain; charset=utf-8" else "text/html; charset=utf-8",
        body = draft.body, subject = draft.subject,
        to = fields.to, cc = fields.cc, bcc = fields.bcc,
        attachments = draft.attachments.map { OutgoingMimeAttachment(it.name, it.mimeType, it.bytes) },
    ).toByteArray(Charsets.UTF_8)
    try {
        val result = PgpEncryptor.encrypt(content, listOf(ownKey), signer)
        if (result !is EncryptResult.Ok) return null
        return wrapAsPgpMime(OutgoingEnvelope(from, fields.to, emptyList(), date), result.armored)
    } finally {
        content.fill(0)
    }
}
