package org.kysecurity.mail.pgp

internal sealed class EnrollmentRow {
    /** Not paired: there is no account to hold a key for. */
    object Hidden : EnrollmentRow()

    object HostileLocation : EnrollmentRow()
    object NoSecureLockScreen : EnrollmentRow()

    /** The vault key is gone — a biometric enrollment change, a Keystore invalidation. Offers the
     *  ceremony again. */
    object KeyInvalidated : EnrollmentRow()

    /** This device holds a key. Offers removal. */
    object Enrolled : EnrollmentRow()

    /** The account's key is held by the server. Offers webmail — this is the retirement nudge. */
    object ServerHeldKey : EnrollmentRow()

    /** The account has no PGP identity yet. Offers webmail, where one can be made. */
    object NoIdentity : EnrollmentRow()

    /** The account could not be reached. Offers nothing, and says so without implying "no". */
    object CouldNotCheck : EnrollmentRow()

    /** A client-protected key this device does not hold yet. Offers the ceremony. */
    object NotEnrolled : EnrollmentRow()
}

/** Local facts before network facts: an offline device must still be told it cannot read mail. */
internal fun enrollmentRowFor(
    paired: Boolean,
    hostileLocation: Boolean,
    hasSecureLockScreen: Boolean,
    status: EnrollmentStatus,
    identity: IdentityCheck,
): EnrollmentRow = when {
    !paired -> EnrollmentRow.Hidden
    hostileLocation -> EnrollmentRow.HostileLocation
    !hasSecureLockScreen -> EnrollmentRow.NoSecureLockScreen

    // Local, and both unsafe to withhold.
    status == EnrollmentStatus.KEY_INVALIDATED -> EnrollmentRow.KeyInvalidated
    status.isEnrolled() -> EnrollmentRow.Enrolled

    else -> when (identity) {
        is IdentityCheck.ServerHeld -> EnrollmentRow.ServerHeldKey
        is IdentityCheck.NoIdentity -> EnrollmentRow.NoIdentity
        is IdentityCheck.CouldNotCheck -> EnrollmentRow.CouldNotCheck
        is IdentityCheck.ClientProtected -> EnrollmentRow.NotEnrolled
    }
}
