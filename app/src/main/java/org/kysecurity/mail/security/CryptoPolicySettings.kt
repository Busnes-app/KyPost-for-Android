package org.kysecurity.mail.security

import android.content.Context

/** "Refuse legacy encryption": also closes the archive-read exception in `docs/STRONG-CRYPTO.md`
 *  (keys below the floor, 64-bit-block ciphers). New mail is strong either way. Plain prefs, one
 *  boolean, no secret; [SecurityWipe] keeps it so a wipe never quietly weakens the posture. */
class CryptoPolicySettings(context: Context) {
    private val prefs = context.applicationContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    var refuseLegacy: Boolean
        get() = prefs.getBoolean(KEY_REFUSE_LEGACY, false)
        set(value) {
            prefs.edit().putBoolean(KEY_REFUSE_LEGACY, value).commit()
        }

    companion object {
        internal const val PREFS_NAME = "org.kysecurity.mail.crypto_policy"
        private const val KEY_REFUSE_LEGACY = "refuse_legacy"
    }
}
