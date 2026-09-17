package org.kysecurity.mail.pgp

/** Why enrollment cannot start at all. Distinct from [FailureReason]: nothing was minted yet. */
internal enum class UnavailableReason {
    NOT_PAIRED,
    HOSTILE_LOCATION,
    NO_SECURE_LOCK_SCREEN,
    NO_IDENTITY,
    SERVER_HELD_KEY,

    /** "Could not check" is not "no": copy that reads as "you don't use encrypted mail" misleads. */
    COULD_NOT_CHECK,
}

/** A closed set, deliberately: no server text is ever rendered from these. */
internal enum class FailureReason {
    /** The server refused the enrollment key for a reason that is not 401 or 429. */
    PUBLISH_REJECTED,

    /** 401 on any call. This device's credential is not accepted; re-pairing is the fix. */
    UNAUTHORIZED,

    RATE_LIMITED,

    /** The envelope did not parse, or its fields were the wrong size. Never a retry. */
    ENVELOPE_MALFORMED,

    /** GCM authentication failed. The copy **describes rather than accuses**; never a retry. */
    COULD_NOT_OPEN,

    /** Discovered at the seal rather than the gate — the lock screen was removed mid-ceremony. */
    NO_SECURE_LOCK_SCREEN,

    SEAL_FAILED,

    /** The keyring inside a v3 envelope is not the one the server recorded delivering, or cannot
     *  replace what this device already holds. Nothing was saved; never a retry. */
    KEYRING_REJECTED,

    /** The keys were sealed on this device, but the server refused to record the device as
     *  enrolled with them: the account moved on in between. Re-enrolling is the only fix, and
     *  repeating the same claim is not tried. */
    ACKNOWLEDGEMENT_REFUSED,

    /** The Keystore would not mint or return the agreement keypair; nothing was published. */
    NO_DEVICE_KEY,
}

/** Every state the ceremony screen can be in. `Reporting` is deliberately absent. */
internal sealed class EnrollmentUiState {
    object CheckingIdentity : EnrollmentUiState()

    data class Unavailable(val reason: UnavailableReason) : EnrollmentUiState()

    object PublishingKey : EnrollmentUiState()

    /** [expiresAtEpochMs] is the end of the current 120-second bucket, for the countdown. */
    data class ShowingCode(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    /** Carries the code because "Check again" resumes rather than restarts; keeps the keypair. */
    data class WaitingTimedOut(val code: String, val expiresAtEpochMs: Long) : EnrollmentUiState()

    object Opening : EnrollmentUiState()

    object AwaitingAuth : EnrollmentUiState()

    /** Carries **no code, deliberately**: the browser already sealed, and a stale code is the alarm. */
    object ReadyToFinish : EnrollmentUiState()

    object Enrolled : EnrollmentUiState()

    data class Failed(val reason: FailureReason) : EnrollmentUiState()
}

/** Omit a state that needs this and the user is stranded — Close destroys the published key. */
internal fun offersCheckAgain(state: EnrollmentUiState, idle: Boolean): Boolean =
    idle && (
        state is EnrollmentUiState.ShowingCode ||
            state is EnrollmentUiState.WaitingTimedOut ||
            state is EnrollmentUiState.ReadyToFinish
        )
