package org.kysecurity.mail.data

/** What `EmailDao.getByFolder` reads for [this] row, for JVM fakes of the DAO. */
fun EmailEntity.toListRow() = EmailListRow(
    messageId = messageId,
    folder = folder,
    sender = sender,
    sentTo = sentTo,
    cc = cc,
    bcc = bcc,
    subject = subject,
    preview = preview,
    hasBody = !body.isNullOrBlank(),
    bodyMode = bodyMode,
    label = label,
    keywordsJson = keywordsJson,
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
