package org.kysecurity.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, ENROLLED_KEYRING, NO_KEY, KEY_INVALIDATED, NO_BLOB }

/** This device can open what it sealed: legacy armor or a prepared keyring. */
internal fun EnrollmentStatus.isEnrolled(): Boolean =
    this == EnrollmentStatus.ENROLLED || this == EnrollmentStatus.ENROLLED_KEYRING

/**
 * What the worker tells the server for a probed status; null means "say nothing". A keyring
 * record is confirmed with the values stored beside it, never restated as the legacy boolean.
 * `NotEnrolled` makes the server forget the delivery it recorded for this device, so it is sent
 * only on a proven loss: the Keystore's own invalidation verdict, or a deliberate teardown
 * ([tornDown], the marker `EnrollmentTeardown` leaves). A probe that merely threw, or found no
 * record on an ordinary unlock (which is also what a device awaiting its first delivery looks
 * like), proves nothing and must not speak for the device.
 */
internal fun enrollmentReportFor(
    status: EnrollmentStatus,
    ack: EnrollmentReport.Keyring?,
    tornDown: Boolean = false,
): EnrollmentReport? = when (status) {
    EnrollmentStatus.ENROLLED -> EnrollmentReport.Legacy
    EnrollmentStatus.ENROLLED_KEYRING -> ack
    EnrollmentStatus.KEY_INVALIDATED -> EnrollmentReport.NotEnrolled
    EnrollmentStatus.NO_BLOB -> if (tornDown) EnrollmentReport.NotEnrolled else null
    EnrollmentStatus.NO_KEY -> null
}

/** Probes the keystore, never cached bookkeeping: a cached boolean survives key destruction. */
internal fun probeEnrollment(vault: EnrollmentVault): EnrollmentStatus {
    return try {
        // Inside the try: stored() forces the lazy prefs, and this function must report, never throw.
        val stored = vault.stored()
        vault.secretKey()
        when {
            stored == null -> EnrollmentStatus.NO_BLOB
            vault.openCipher(stored.iv) == null -> EnrollmentStatus.KEY_INVALIDATED
            stored.kind == VaultRecordKind.KEYRING -> EnrollmentStatus.ENROLLED_KEYRING
            else -> EnrollmentStatus.ENROLLED
        }
    } catch (e: KeyPermanentlyInvalidatedException) {
        EnrollmentStatus.KEY_INVALIDATED
    } catch (e: Exception) {
        EnrollmentStatus.NO_KEY
    }
}
