package org.kysecurity.mail.mail

import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Where a web link in a message really goes. [url] is what gets opened, so the [host] the user
 *  confirmed and the page that loads come from one parse. [host] is lowercase ASCII: an IDN shows
 *  as `xn--`, which keeps a lookalike from passing as the real name. */
class LinkTarget(val host: String, val url: HttpUrl)

/** Null for anything that is not a well-formed http(s) URL with a host. */
fun linkTargetOf(raw: String): LinkTarget? {
    val url = raw.trim().toHttpUrlOrNull() ?: return null
    if (url.host.isBlank()) return null
    return LinkTarget(url.host, url)
}
