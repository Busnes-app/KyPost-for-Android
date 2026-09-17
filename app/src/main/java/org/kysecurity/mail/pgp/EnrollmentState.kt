package org.kysecurity.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, ENROLLED_KEYRING, NO_KEY, KEY_INVALIDATED, NO_BLOB }

/** This device can open what it sealed: legacy armor or a prepared keyring. */
internal fun EnrollmentStatus.isEnrolled(): Boolean =
    this == EnrollmentStatus.ENROLLED || this == EnrollmentStatus.ENROLLED_KEYRING

/** What the worker tells the server for a probed status. A keyring record is confirmed with the
 *  values stored beside it, never restated as the legacy boolean; without them there is nothing
 *  truthful to send, so null means "say nothing" (false would wipe the server's delivery record). */
internal fun enrollmentReportFor(status: EnrollmentStatus, ack: EnrollmentReport.Keyring?): EnrollmentReport? = when (status) {
    EnrollmentStatus.ENROLLED -> EnrollmentReport.Legacy
    EnrollmentStatus.ENROLLED_KEYRING -> ack
    EnrollmentStatus.NO_KEY, EnrollmentStatus.KEY_INVALIDATED, EnrollmentStatus.NO_BLOB -> EnrollmentReport.NotEnrolled
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
