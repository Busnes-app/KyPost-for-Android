package org.kysecurity.mail.pgp

internal sealed class KeyringImportOutcome {
    /** Validated, durably sealed, and installed as the session, in that order. */
    object Imported : KeyringImportOutcome()

    /** The exact bytes already sealed on this device; nothing was rewritten. */
    object Replayed : KeyringImportOutcome()

    /** Not a complete ring naming the committed active key. Nothing was touched. */
    object InvalidRing : KeyringImportOutcome()

    /** A different ring, or legacy material, is already sealed here. Replacement rules for
     *  conversion and retirement are a server contract that does not exist yet, so the previous
     *  record is kept and this one is dropped. */
    object RefusedIncomparable : KeyringImportOutcome()

    object Cancelled : KeyringImportOutcome()
    object NoSecureLockScreen : KeyringImportOutcome()
    data class Failed(val message: String) : KeyringImportOutcome()
}

/**
 * Local import of an authenticated `kypost-pgp-keyring-v1` plaintext. No Android, no transport:
 * the caller has already opened the envelope, and nothing here acknowledges anything to a server.
 *
 * Order is the contract: validate the entire ring against [expectedActiveFingerprint] (the key
 * the AAD committed to) before the vault or session is touched; establish that replacing the
 * previous record is safe; seal and durably store the original bytes; only then install the
 * session from the bytes that were committed and call [onLocalComplete]. A future acknowledgement
 * runs from that callback and nowhere earlier. Every other exit leaves the previous record and
 * session exactly as they were.
 */
internal suspend fun importKeyring(
    plaintext: ByteArray,
    expectedActiveFingerprint: String,
    previousVault: VaultOpener,
    sealer: VaultSealer,
    onLocalComplete: () -> Unit,
): KeyringImportOutcome {
    val ring = parsePgpKeyring(plaintext, expectedActiveFingerprint) ?: return KeyringImportOutcome.InvalidRing

    val previousHeld = EnrollmentSession.isHeld() || when (val opened = previousVault.open()) {
        OpenOutcome.Opened -> true
        OpenOutcome.NotEnrolled -> false
        OpenOutcome.Cancelled -> return ring.dropWith(KeyringImportOutcome.Cancelled)
        OpenOutcome.NoSecureLockScreen -> return ring.dropWith(KeyringImportOutcome.NoSecureLockScreen)
        is OpenOutcome.Failed -> return ring.dropWith(KeyringImportOutcome.Failed(opened.message))
    }
    if (previousHeld) {
        // Equal inventories or active keys prove nothing about certifications or revocations;
        // only the identical bytes are known to be the same ring.
        val identical = EnrollmentSession.withKeyring { it.original.contentEquals(ring.original) } ?: false
        if (!identical) return ring.dropWith(KeyringImportOutcome.RefusedIncomparable)
        ring.wipe()
        onLocalComplete()
        return KeyringImportOutcome.Replayed
    }

    return when (val sealed = sealer.seal(ring.original, VaultRecordKind.KEYRING)) {
        SealOutcome.Sealed -> {
            EnrollmentSession.putKeyring(ring)
            onLocalComplete()
            KeyringImportOutcome.Imported
        }
        SealOutcome.Cancelled -> ring.dropWith(KeyringImportOutcome.Cancelled)
        SealOutcome.NoSecureLockScreen -> ring.dropWith(KeyringImportOutcome.NoSecureLockScreen)
        is SealOutcome.Failed -> ring.dropWith(KeyringImportOutcome.Failed(sealed.message))
    }
}

private fun PgpKeyring.dropWith(outcome: KeyringImportOutcome): KeyringImportOutcome {
    wipe()
    return outcome
}
