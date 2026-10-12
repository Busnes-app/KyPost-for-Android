package org.kysecurity.mail

import android.content.Intent
import android.net.Uri

internal data class ComposePrefill(
    val to: String,
    val subject: String,
    val bodyHtml: String,
)

internal fun Intent.isExternalComposeIntent(): Boolean =
    action == Intent.ACTION_SENDTO || action == Intent.ACTION_SEND || action == Intent.ACTION_SEND_MULTIPLE

/** Normalizes compose intents before any value reaches the editor. Only [internal] launches
 *  (the non-exported alias) may carry HTML; every other caller gets public extras as plain text. */
internal fun parseComposeIntent(
    intent: Intent,
    internal: Boolean,
    plainTextToHtml: (String) -> String,
): ComposePrefill {
    if (intent.action == Intent.ACTION_SENDTO && intent.data?.scheme.equals("mailto", ignoreCase = true)) {
        val uri = intent.data!!
        // MailTo.parse decodes the whole query before splitting on older Android releases,
        // so an encoded '=' inside a value is mistaken for another separator.
        val headers = uri.encodedQuery.orEmpty()
            .split('&')
            .mapNotNull { part ->
                val separator = part.indexOf('=')
                if (separator < 0) null else {
                    Uri.decode(part.substring(0, separator)).lowercase() to
                        Uri.decode(part.substring(separator + 1))
                }
            }
            .toMap()
        return ComposePrefill(
            to = Uri.decode(uri.encodedSchemeSpecificPart.substringBefore('?')),
            subject = headers["subject"].orEmpty(),
            bodyHtml = plainTextToHtml(headers["body"].orEmpty()),
        )
    }

    if (internal) {
        return ComposePrefill(
            to = intent.getStringExtra(ComposeActivity.EXTRA_TO).orEmpty(),
            subject = intent.getStringExtra(ComposeActivity.EXTRA_SUBJECT).orEmpty(),
            bodyHtml = intent.getStringExtra(ComposeActivity.EXTRA_BODY_HTML)
                ?: plainTextToHtml(intent.getStringExtra(ComposeActivity.EXTRA_BODY).orEmpty()),
        )
    }
    return ComposePrefill(
        to = intent.getStringArrayExtra(Intent.EXTRA_EMAIL)?.joinToString(", ").orEmpty(),
        subject = intent.getStringExtra(Intent.EXTRA_SUBJECT).orEmpty(),
        bodyHtml = plainTextToHtml(intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString().orEmpty()),
    )
}
