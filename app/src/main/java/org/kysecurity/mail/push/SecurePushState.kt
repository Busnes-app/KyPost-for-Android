package org.kysecurity.mail.push

import android.content.Context
import android.content.SharedPreferences
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import org.kysecurity.mail.security.openEncryptedPrefs
import java.io.IOException

internal const val SECURE_PUSH_STATE_PREFS = "push_state_secure"

internal const val KEY_HISTORY_JSON = "history_json"
internal const val KEY_UNIFIEDPUSH_ENDPOINT = "unifiedpush_endpoint"
internal const val KEY_UNIFIEDPUSH_P256DH = "unifiedpush_p256dh"
internal const val KEY_UNIFIEDPUSH_AUTH = "unifiedpush_auth"

/** Moved here from the plaintext `push_state` DataStore, under the same names. */
internal val SECURE_PUSH_KEYS = listOf(KEY_HISTORY_JSON, KEY_UNIFIEDPUSH_ENDPOINT, KEY_UNIFIEDPUSH_P256DH, KEY_UNIFIEDPUSH_AUTH)

/** Push history and the UnifiedPush WebPush keys, in a Keystore-backed encrypted file.
 *  Construction is disk and Keystore I/O, like [SecurePairingStore]. */
class SecurePushState internal constructor(private val prefs: SharedPreferences) {
    constructor(context: Context) : this(
        openEncryptedPrefs(context, SECURE_PUSH_STATE_PREFS) {
            android.util.Log.e("SecurePushState", "Encrypted push state keyset is undecryptable", it)
        },
    )

    private val _values = MutableStateFlow(read())
    val values: StateFlow<Map<String, String>> = _values.asStateFlow()

    /** One edit at a time: [block] reads [values] and writes the editor as one unit. */
    @Synchronized
    fun edit(block: (current: Map<String, String>, editor: SharedPreferences.Editor) -> Unit) {
        val editor = prefs.edit()
        block(_values.value, editor)
        if (!editor.commit()) throw IOException("Could not write $SECURE_PUSH_STATE_PREFS")
        _values.value = read()
    }

    private fun read(): Map<String, String> =
        prefs.all.mapNotNull { (key, value) -> (value as? String)?.let { key to it } }.toMap()
}

/** Moves [SECURE_PUSH_KEYS] out of [plain]: copy and commit first, remove second, so a crash in
 *  between leaves the same values in both and the rerun repeats both steps. Returns whether
 *  [plain] is now empty. */
internal suspend fun migratePlaintextPushState(
    plain: DataStore<Preferences>,
    secure: SecurePushState,
    dropHistory: Boolean,
): Boolean {
    val old = plain.data.first()
    secure.edit { _, editor ->
        SECURE_PUSH_KEYS.forEach { name ->
            val value = old[stringPreferencesKey(name)]
            if (value != null && !(dropHistory && name == KEY_HISTORY_JSON)) editor.putString(name, value)
        }
    }
    var empty = false
    plain.edit { prefs ->
        SECURE_PUSH_KEYS.forEach { prefs.remove(stringPreferencesKey(it)) }
        empty = prefs.asMap().isEmpty()
    }
    return empty
}
