package org.kysecurity.mail.signon

object KyIdentitySignOn {
    /** getAuthToken option read by KyAuth: the relay URL as typed. KyAuth normalises, shows and signs it. */
    const val OPTION_ORIGIN = "org.kysecurity.identity.origin"
}

/** The relay URL exactly as typed, minus surrounding whitespace. */
fun typedRelayUrl(raw: String): String = raw.trim()
