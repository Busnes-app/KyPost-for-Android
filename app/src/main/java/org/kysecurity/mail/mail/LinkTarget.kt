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

/** Link text that reads as a web address. Words, sentences and e-mail addresses do not. */
private val URL_LIKE_TEXT = Regex("""^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(:\d+)?([/?#]\S*)?$""", RegexOption.IGNORE_CASE)

/** The host [href] really goes to, when the visible [text] reads as an address on a different
 *  one; null when they agree or the text is not an address. `www.` is ignored on both sides, and
 *  a subdomain of the shown host counts as the same site; `bank.example.evil.tld` is not. */
fun linkTextMismatch(text: String, href: String): String? {
    val shown = text.trim()
    if (!URL_LIKE_TEXT.matches(shown)) return null
    val real = linkTargetOf(href)?.host ?: return null
    val claimed = linkTargetOf(if ("://" in shown) shown else "https://$shown")?.host ?: return null
    val realSite = real.removePrefix("www.")
    val claimedSite = claimed.removePrefix("www.")
    return real.takeUnless { realSite == claimedSite || realSite.endsWith(".$claimedSite") }
}
