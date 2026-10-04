package org.kysecurity.mail.signon

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** scheme://host:port/path, normalised by OkHttp; null when it is not an http(s) URL. */
internal fun canonicalOrigin(url: String?): String? =
    url?.toHttpUrlOrNull()?.let { "${it.scheme}://${it.host}:${it.port}${it.encodedPath.trimEnd('/')}" }

/** Both sides must parse; two unparseable values are not the same issuer. */
internal fun sameIssuer(a: String?, b: String?): Boolean {
    val x = canonicalOrigin(a) ?: return false
    return x == canonicalOrigin(b)
}
