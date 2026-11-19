package org.kysecurity.mail.pgp

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

private const val INBOX = "INBOX"
private const val DRAFTS = "Drafts"

/** `tab` is omitted so ReadPage searches every tab; INBOX travels as an absent `mailbox`. */
fun webmailMessageUrl(serverUrl: String, mailbox: String, messageId: String): String? {
    if (messageId.isBlank()) return null
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder()
        .apply {
            if (mailbox.isNotBlank() && !mailbox.equals(INBOX, ignoreCase = true)) {
                addQueryParameter("mailbox", mailbox)
            }
        }
        .addQueryParameter("message", messageId)
        .build()
        .toString()
}

/** Drafts is passed explicitly — an absent `mailbox` means INBOX to the web read page. */
fun webmailDraftsUrl(serverUrl: String): String? {
    val base = "${serverUrl.trimEnd('/')}/read".toHttpUrlOrNull() ?: return null
    return base.newBuilder().addQueryParameter("mailbox", DRAFTS).build().toString()
}

/** Path, query and fragment are all cleared so a stored `serverUrl` cannot carry them through. */
fun webmailHomeUrl(serverUrl: String): String? =
    serverUrl.toHttpUrlOrNull()?.newBuilder()?.encodedPath("/")?.query(null)?.fragment(null)
        ?.build()?.toString()

/** The web's first sign-in encryption setup page (KyPost-Server docs/E2E_PGP.md). */
fun webmailEncryptionSetupUrl(serverUrl: String): String? =
    "${serverUrl.trimEnd('/')}/setup/encryption".toHttpUrlOrNull()?.toString()
