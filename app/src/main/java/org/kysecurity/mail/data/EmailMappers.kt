package org.kysecurity.mail.data

import org.kysecurity.mail.Email
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

private val mapperJson = Json { ignoreUnknownKeys = true }

/** List rows carry no body; [Email.hasBody] says whether one is cached. */
fun EmailListRow.toUiEmail(): Email = Email(
    id = messageId,
    subject = subject,
    sender = sender,
    preview = preview,
    keywords = runCatching { mapperJson.decodeFromString<List<String>>(keywordsJson) }.getOrDefault(emptyList()).toSet(),
    folder = folder,
    sentTo = sentTo,
    cc = cc,
    bcc = bcc,
    hasBody = hasBody,
    bodyMode = bodyMode,
    label = label,
    status = status,
    atUtc = atUtc,
    wokenAt = wokenAt,
    hasAttachments = hasAttachments,
    sourceMode = sourceMode,
    pgpEncrypted = pgpEncrypted,
    pgpSigned = pgpSigned,
    pgpVerified = pgpVerified,
    pgpSignerFingerprint = pgpSignerFingerprint,
    pgpDecryptError = pgpDecryptError,
)

fun Email.toEntity(folder: String, sourceMode: String): EmailEntity = EmailEntity(
    messageId = id,
    folder = folder,
    sender = sender,
    sentTo = sentTo,
    cc = cc,
    bcc = bcc,
    subject = subject,
    preview = preview,
    body = body,
    bodyMode = bodyMode,
    label = label,
    keywordsJson = mapperJson.encodeToString(keywords.toList()),
    status = status,
    atUtc = atUtc,
    wokenAt = wokenAt,
    hasAttachments = hasAttachments,
    sourceMode = sourceMode,
    pgpEncrypted = pgpEncrypted,
    pgpSigned = pgpSigned,
    pgpVerified = pgpVerified,
    pgpSignerFingerprint = pgpSignerFingerprint,
    pgpDecryptError = pgpDecryptError,
)
