package org.kysecurity.mail.pgp

/** [CouldNotCheck] is deliberately distinct from [NoIdentity] — see [UnavailableReason]. */
internal sealed class IdentityCheck {
    /** The only case enrollment may proceed from. [fingerprint] is what the envelope's AAD binds;
     *  it is hashed from the key bytes by [ownFingerprintFromBootstrap], never read off a server
     *  field sitting beside them. */
    data class ClientProtected(val fingerprint: String) : IdentityCheck()

    object ServerHeld : IdentityCheck()
    object NoIdentity : IdentityCheck()
    object CouldNotCheck : IdentityCheck()
}

internal interface IdentitySource {
    suspend fun check(): IdentityCheck
}

/** The enrollment calls. The real implementation **must** use `pinnedPairingCallFactory`. */
internal interface EnrollmentTransport {
    /** This device's paired id — hashed into the code and bound into the envelope's AAD. Null when
     *  there is no usable pairing, which the ceremony reports as [UnavailableReason.NOT_PAIRED]. */
    suspend fun deviceId(): String?

    suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult

    suspend fun fetchEnvelope(): EnrollmentCallResult

    suspend fun reportEnrolled(enrolled: Boolean): EnrollmentCallResult

    /** Hands the report to [EnrollmentStateWorker], which re-probes live state and retries. Called
     *  when the direct report failed and the device is nonetheless enrolled. */
    fun enqueueDurableReport()
}

/** A port rather than a direct [EnrollmentKeyStore] call so "delete on every exit" is testable. */
internal interface EnrollmentKeys {
    /** Mints a fresh keypair for one ceremony, destroying any previous one. */
    fun newKeyPair(): Boolean

    /** The uncompressed SEC1 point, `0x04 ‖ X ‖ Y`. **The code derives from this** — never from
     *  anything the server sent back, and never from a cached copy of what was published. */
    fun rawPublicKey(): ByteArray?

    /** The base64 of the same point, as published. */
    fun encodedPublicKey(): String?

    fun sharedSecret(epk: ByteArray): ByteArray?

    fun deleteKeyPair(): Boolean
}

internal sealed class SealOutcome {
    /** Sealed **and stored**. The sealer owns the ciphertext end to end so that no key material
     *  passes back through the state machine. */
    object Sealed : SealOutcome()

    /** The user dismissed the prompt, or the Activity hosting it was destroyed. Not a failure: the
     *  ceremony returns to the code and keeps polling, so the user can try again. */
    object Cancelled : SealOutcome()

    object NoSecureLockScreen : SealOutcome()

    data class Failed(val message: String) : SealOutcome()
}

/** The re-seal, behind an interface because `BiometricPrompt` is Activity-bound. */
internal interface VaultSealer {
    suspend fun seal(plaintext: ByteArray, kind: VaultRecordKind): SealOutcome
}

/** The locally cached plaintext of mail the server decrypted; enrolling is what drops it. */
internal interface DecryptedMailCache {
    /** @return the number of cached messages whose plaintext was dropped. */
    suspend fun clearServerDecryptedBodies(): Int
}

/** Wall clock for the bucket (it must match the browser's), monotonic for the poll deadline. */
internal interface EnrollmentClock {
    fun epochSeconds(): Long
    fun elapsedRealtimeMs(): Long

    /** Injected rather than calling `delay` directly so a JVM test runs the five-minute polling
     *  window in microseconds without a test dispatcher — this module has no
     *  `kotlinx-coroutines-test` on the classpath. */
    suspend fun sleep(millis: Long)
}
