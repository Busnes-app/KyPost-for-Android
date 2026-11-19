package org.kysecurity.mail

import android.content.Context
import android.content.SharedPreferences

class MailSettings(context: Context) {
    private val prefs: SharedPreferences = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun isPaired(): Boolean = prefs.getBoolean(KEY_PAIRED, false)

    fun setPaired(paired: Boolean) {
        prefs.edit().putBoolean(KEY_PAIRED, paired).apply()
    }

    /** The server's `conversations` switch as last read; on until the server says otherwise. */
    fun conversations(): Boolean = prefs.getBoolean(KEY_CONVERSATIONS, true)

    fun setConversations(enabled: Boolean) {
        prefs.edit().putBoolean(KEY_CONVERSATIONS, enabled).apply()
    }

    companion object {
        private const val PREFS_NAME = "org.kysecurity.mail.settings"
        private const val KEY_PAIRED = "paired"
        private const val KEY_CONVERSATIONS = "conversations"
    }
}

