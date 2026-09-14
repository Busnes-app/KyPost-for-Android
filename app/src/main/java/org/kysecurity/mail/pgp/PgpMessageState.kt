package org.kysecurity.mail.pgp

enum class PgpMessageState {
    /** No OpenPGP content: render normally. */
    NONE,

    /** Encrypted, and the server deliberately did not decrypt: the key is end-to-end held. */
    CLIENT_PROTECTED,

    /** Encrypted, and the server tried to decrypt and failed. There is a real error to show. */
    DECRYPT_FAILED,

    /** Encrypted, and the server decrypted it — surfaced so the user knows the server read it. */
    DECRYPTED_BY_SERVER,

    /** Encrypted, not cached: an absent body is not evidence of client-side protection. */
    BODY_UNAVAILABLE,
}

// Ordering matters: pgpDecryptError is checked before the body, which the server leaves empty.
fun pgpMessageStateOf(
    pgpEncrypted: Boolean,
    pgpDecryptError: String,
    body: String?,
    /** True when the body could not be read at all (no cached row), as opposed to the server
     *  having delivered the message with no body. See [PgpMessageState.BODY_UNAVAILABLE]. */
    bodyUnavailable: Boolean = false,
): PgpMessageState = when {
    !pgpEncrypted -> PgpMessageState.NONE
    pgpDecryptError.isNotBlank() -> PgpMessageState.DECRYPT_FAILED
    !body.isNullOrBlank() -> PgpMessageState.DECRYPTED_BY_SERVER
    bodyUnavailable -> PgpMessageState.BODY_UNAVAILABLE
    else -> PgpMessageState.CLIENT_PROTECTED
}

/** An unwarmed encrypted message looks unencrypted on the wire (`pgpEncrypted` is `omitempty`). */
fun rendersNothing(state: PgpMessageState, body: String?, preview: String): Boolean =
    state == PgpMessageState.NONE && body.isNullOrBlank() && preview.isBlank()

/** VERIFIED_CONFIRMED, SIGNER_UNKNOWN and KEY_CHANGED come only from [signatureStateFor]. */
enum class PgpSignatureState {
    /** No opinion was expressed. Nothing to say. */
    NONE,

    /** Decrypted, with neither a packet signature nor a declared PGP/MIME signature wrapper.
     *  A statement about the message,
     *  never about the sender: no glyph stronger than "nothing to say". Only
     *  [EncryptedMessageReader] produces it; the inbox flags cannot tell it from [NONE]. */
    UNSIGNED,

    /** Signed by a key bound to the sender, and the user confirmed that key out of band — by
     *  eyeballing the fingerprint or scanning a QR code. The only state that claims identity. */
    VERIFIED_CONFIRMED,

    /** Same key as last time (TOFU pin) — claims continuity, never identity. */
    VERIFIED_SEEN_BEFORE,

    /** Signed by no key we hold for this sender — not an accusation, the causes are alike. */
    SIGNER_UNKNOWN,

    /**
     * A key IS bound to this sender and it no longer matches its TOFU pin.
     */
    KEY_CHANGED,

    /** Signed, and it does **not** verify against the key bound to the sender. */
    INVALID,
}

/** A blank `pgpSignerFingerprint` means nothing was checked — never an accusation. */
fun pgpSignatureStateOf(
    pgpSigned: Boolean,
    pgpVerified: Boolean,
    pgpSignerFingerprint: String = "",
): PgpSignatureState = when {
    !pgpSigned -> PgpSignatureState.NONE
    pgpVerified -> PgpSignatureState.VERIFIED_SEEN_BEFORE
    pgpSignerFingerprint.isBlank() -> PgpSignatureState.SIGNER_UNKNOWN
    else -> PgpSignatureState.INVALID
}

/** [PgpMessageState.DECRYPTED_BY_SERVER] is deliberately unmarked: the row reads normally. */
fun pgpRowMarker(
    state: PgpMessageState,
    /** Outranks every readability marker; SIGNER_UNKNOWN deliberately does not mark. */
    signature: PgpSignatureState = PgpSignatureState.NONE,
): String? = when (signature) {
    // KEY_CHANGED is unreachable from pgpSignatureStateOf today; kept for a future local verdict.
    PgpSignatureState.INVALID, PgpSignatureState.KEY_CHANGED -> "⚠"
    else -> pgpReadabilityMarker(state)
}

private fun pgpReadabilityMarker(state: PgpMessageState): String? = when (state) {
    PgpMessageState.CLIENT_PROTECTED -> "🔒"
    PgpMessageState.DECRYPT_FAILED -> "⚠"
    // BODY_UNAVAILABLE is unmarked: we do not know which state applies, and a lock glyph would be
    // the very claim we cannot substantiate.
    PgpMessageState.NONE, PgpMessageState.DECRYPTED_BY_SERVER, PgpMessageState.BODY_UNAVAILABLE -> null
}
