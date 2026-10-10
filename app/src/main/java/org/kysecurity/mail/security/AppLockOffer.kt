package org.kysecurity.mail.security

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.appcompat.app.AlertDialog
import org.kysecurity.mail.R

/** The one-time "lock KyPost?" suggestion after a first pairing. Never forced: dismissing it is
 *  an answer, and it is not asked again on this install. */
object AppLockOffer {
    private const val PREFS_NAME = "org.kysecurity.mail.app_lock_offer"
    private const val KEY_OFFERED = "offered"

    /** Spent when shown, not when answered, so a rotation or Back cannot turn it into a nag. */
    fun showIfDue(activity: Activity) {
        val prefs = activity.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
        val lockEnabled = SecurityRuntime.graph(activity).appLockStore.isLockEnabled()
        if (!shouldOfferAppLock(lockEnabled, prefs.getBoolean(KEY_OFFERED, false))) return
        // commit(): an offer recorded asynchronously can be lost to a process death and repeated.
        prefs.edit().putBoolean(KEY_OFFERED, true).commit()
        AlertDialog.Builder(activity)
            .setTitle(R.string.app_lock_offer_title)
            .setMessage(R.string.app_lock_offer_message)
            .setPositiveButton(R.string.app_lock_offer_accept) { _, _ ->
                activity.startActivity(Intent(activity, SecuritySettingsActivity::class.java))
            }
            .setNegativeButton(R.string.app_lock_offer_decline, null)
            .create()
            .showSecurely()
    }
}

internal fun shouldOfferAppLock(lockEnabled: Boolean, alreadyOffered: Boolean): Boolean =
    !lockEnabled && !alreadyOffered
