package org.kysecurity.mail.pgp

import android.security.keystore.KeyPermanentlyInvalidatedException

internal enum class EnrollmentStatus { ENROLLED, ENROLLED_KEYRING, NO_KEY, KEY_INVALIDATED, NO_BLOB }

/** This device can open what it sealed: legacy armor or a prepared keyring. */
internal fun EnrollmentStatus.isEnrolled(): Boolean =
    this == EnrollmentStatus.ENROLLED || this == EnrollmentStatus.ENROLLED_KEYRING

/** The one boolean the relay understands means "this device opens its v2 envelope". A prepared
 *  keyring is not that, and the server has no field yet that it is; reporting it as legacy
 *  enrollment would claim a protocol state that does not exist. */
internal fun EnrollmentStatus.legacyReportValue(): Boolean = this == EnrollmentStatus.ENROLLED

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
