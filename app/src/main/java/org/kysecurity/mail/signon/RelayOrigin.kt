package org.kysecurity.mail.signon

import org.kysecurity.mail.push.pairingEndpoint

object KyIdentitySignOn {
    /** getAuthToken option read by KyAuth: the canonical origin of the relay URL KyPost connects to. */
    const val OPTION_ORIGIN = "org.kysecurity.identity.origin"
}

/** Canonical origin of the URL the client connects to (same parser), or null if the client would refuse it. */
fun relayOrigin(serverUrl: String): String? {
    val url = pairingEndpoint(serverUrl, "/") ?: return null
    return "${url.scheme}://${url.host}" + if (url.port != 443) ":${url.port}" else ""
}
