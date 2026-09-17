package org.kysecurity.mail.pgp

/** What a sealed record's plaintext is. Carried as the record's format byte, so nothing ever
 *  inspects plaintext to decide how to read it. */
internal enum class VaultRecordKind(val recordVersion: Byte) {
    /** One armored secret-key collection, current ring first. */
    LEGACY_ARMOR(1),

    /** The original `kypost-pgp-keyring-v1` bytes, validated before sealing. */
    KEYRING(2),
}

/** [Opened] carries no key material — the plaintext goes straight into [EnrollmentSession]. */
internal sealed class OpenOutcome {
    object Opened : OpenOutcome()
    object Cancelled : OpenOutcome()

    /** No sealed envelope on this device: never enrolled, or torn down by a wipe, an unpair or
     *  Hostile Location Protection. */
    object NotEnrolled : OpenOutcome()

    object NoSecureLockScreen : OpenOutcome()

    /** The envelope exists and could not be opened — typically a Keystore key the OS invalidated,
     *  which needs a fresh enrollment rather than a retry. */
    data class Failed(val message: String) : OpenOutcome()
}

internal interface VaultOpener {
    /** On [OpenOutcome.Opened], and only then, the opened material is in [EnrollmentSession]. */
    suspend fun open(): OpenOutcome

    /** The kind of the record on disk, read without authentication; null when there is none.
     *  Throws when the record cannot be read, so a caller never seals over a record it could
     *  not classify. */
    fun sealedKind(): VaultRecordKind?
}
