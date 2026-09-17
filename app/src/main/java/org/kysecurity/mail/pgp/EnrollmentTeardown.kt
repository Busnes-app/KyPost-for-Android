package org.kysecurity.mail.pgp

import android.content.Context

/** Destroys everything that can open this device's envelope. The vault goes first, deliberately. */
internal object EnrollmentTeardown {
    fun destroy(context: Context): List<String> {
        val failed = mutableListOf<String>()
        val vault = EnrollmentVault(context)
        failed += vault.destroy()
        if (!EnrollmentKeyStore.deleteKeyPair()) failed += "deleteAgreementKey"
        // After destroy, which clears the same store. This is the one signal that lets the worker
        // tell the server "not enrolled"; an ordinary probe never may.
        if (!vault.markTeardownReport()) failed += "markTeardown"
        return failed
    }

    /** [destroy] plus the correction to the server, for "Remove from this device". */
    fun destroyAndReport(context: Context): List<String> {
        val leftBehind = destroy(context)
        EnrollmentStateWorker.enqueue(context)
        return leftBehind
    }
}
