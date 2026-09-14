package org.kysecurity.mail.pgp

/** The two `protection` values this app understands. Anything else degrades to "not server". */
internal const val PROTECTION_SERVER = "server"
internal const val PROTECTION_CLIENT = "client"

data class PgpComposeState(
    val canEncrypt: Boolean,
    val canSign: Boolean,
    /** Neither the server nor this unenrolled device holds the key, so hand off to webmail. */
    val handoffToWebmail: Boolean,
    /** Encrypt here and send via `/api/mail/send-pgp` — client custody on an enrolled device. */
    val clientSide: Boolean = false,
)

// Unknown (null) hides everything; an unrecognized protection degrades to "not server".
fun pgpComposeStateOf(
    hasIdentity: Boolean?,
    protection: String?,
    deviceEnrolled: Boolean = false,
    accountAddress: String = "",
): PgpComposeState = when {
    protection == null || hasIdentity != true ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
    // An enrolled device holds the key the browser sealed to it, so it can do the crypto itself.
    protection == PROTECTION_CLIENT && deviceEnrolled && accountAddress.isNotBlank() ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false, clientSide = true)
    protection == PROTECTION_CLIENT ->
        PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = true)
    protection == PROTECTION_SERVER ->
        PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false)
    else -> PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false)
}

internal enum class DraftHandoffMode { ENCRYPT_AND_SAVE, OPEN_WITHOUT_SAVE, REFUSE }

internal fun draftHandoffMode(
    hasIdentity: Boolean?, protection: String?, enrolled: Boolean, accountAddress: String,
): DraftHandoffMode = when {
    hasIdentity != true || protection != PROTECTION_CLIENT -> DraftHandoffMode.REFUSE
    !enrolled -> DraftHandoffMode.OPEN_WITHOUT_SAVE
    accountAddress.isBlank() -> DraftHandoffMode.REFUSE
    else -> DraftHandoffMode.ENCRYPT_AND_SAVE
}
