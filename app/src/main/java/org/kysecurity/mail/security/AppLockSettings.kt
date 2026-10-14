package org.kysecurity.mail.security

import android.content.Context
import android.content.SharedPreferences

private const val PREFS_NAME = "org.kysecurity.mail.app_lock_settings"
private const val KEY_GRACE_MILLIS = "lock_grace_millis"

/** Plain prefs, not [AppLockStore]: read from onStop, which must not touch the Keystore. */
class AppLockSettings(context: Context) {
    private val prefs: SharedPreferences =
        context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun graceMillis(): Long = prefs.getLong(KEY_GRACE_MILLIS, DEFAULT_GRACE_MILLIS)

    fun setGraceMillis(millis: Long) {
        // commit(), like every other security-relevant write in this package: a process death
        // before an async flush would silently leave the previous window in force.
        prefs.edit().putLong(KEY_GRACE_MILLIS, millis.coerceIn(0L, MAX_GRACE_MILLIS)).commit()
    }

    companion object {
        const val DEFAULT_GRACE_MILLIS = 30_000L
        const val MAX_GRACE_MILLIS = 300_000L

        val OPTIONS_MILLIS = longArrayOf(0L, 30_000L, 60_000L, 300_000L)

        /** A longer window leaves the app open longer in someone else's hand. */
        fun weakensGrace(from: Long, to: Long): Boolean = to > from
    }
}
