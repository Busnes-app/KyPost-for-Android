package org.kysecurity.mail.push

import android.content.SharedPreferences
import androidx.datastore.preferences.core.PreferenceDataStoreFactory
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.longPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SecurePushStateMigrationTest {
    private val dir = File(System.getProperty("java.io.tmpdir"), "push-state-migration-${System.nanoTime()}")
        .apply { mkdirs() }
    private val file = File(dir, "push_state.preferences_pb")
    private val plain = PreferenceDataStoreFactory.create(
        scope = CoroutineScope(SupervisorJob() + Dispatchers.IO),
        produceFile = { file },
    )
    private val backing = MapPrefs()
    private val secure = SecurePushState(backing)

    private suspend fun seedPlaintext(withFlag: Boolean) = plain.edit {
        it[stringPreferencesKey(KEY_HISTORY_JSON)] = HISTORY
        it[stringPreferencesKey(KEY_UNIFIEDPUSH_ENDPOINT)] = "https://up.example/topic"
        it[stringPreferencesKey(KEY_UNIFIEDPUSH_P256DH)] = "p256dh-key"
        it[stringPreferencesKey(KEY_UNIFIEDPUSH_AUTH)] = AUTH
        if (withFlag) it[longPreferencesKey("sync_last_at")] = 5L
    }

    private fun plaintextBytes() = file.readBytes().toString(Charsets.ISO_8859_1)

    @Test
    fun movesSecretsIntoTheEncryptedStoreAndOutOfThePlaintextFile(): Unit = runBlocking {
        seedPlaintext(withFlag = true)
        assertTrue("precondition: the secret is on disk in the clear", plaintextBytes().contains(AUTH))

        val empty = migratePlaintextPushState(plain, secure, dropHistory = false)

        assertEquals(HISTORY, secure.values.value[KEY_HISTORY_JSON])
        assertEquals("https://up.example/topic", secure.values.value[KEY_UNIFIEDPUSH_ENDPOINT])
        assertEquals("p256dh-key", secure.values.value[KEY_UNIFIEDPUSH_P256DH])
        assertEquals(AUTH, secure.values.value[KEY_UNIFIEDPUSH_AUTH])
        assertFalse("a non-secret flag is still there", empty)
        assertEquals(5L, plain.data.first()[longPreferencesKey("sync_last_at")])
        val onDisk = plaintextBytes()
        assertFalse("the auth secret must leave the plaintext file", onDisk.contains(AUTH))
        assertFalse("the history must leave the plaintext file", onDisk.contains("Secret Subject"))
    }

    @Test
    fun reportsAPlaintextStoreItEmptied(): Unit = runBlocking {
        seedPlaintext(withFlag = false)

        assertTrue(migratePlaintextPushState(plain, secure, dropHistory = false))
        assertEquals(emptyMap<Any, Any>(), plain.data.first().asMap())
    }

    @Test
    fun rerunningIsANoOp(): Unit = runBlocking {
        seedPlaintext(withFlag = true)
        migratePlaintextPushState(plain, secure, dropHistory = false)
        val after = secure.values.value
        val plainAfter = plain.data.first().asMap()

        migratePlaintextPushState(plain, secure, dropHistory = false)

        assertEquals(after, secure.values.value)
        assertEquals(plainAfter, plain.data.first().asMap())
    }

    /** The crash window: copied and committed, but the plaintext removal never ran. */
    @Test
    fun aRunInterruptedAfterTheCopyFinishesOnTheNextRun(): Unit = runBlocking {
        seedPlaintext(withFlag = true)
        secure.edit { _, editor -> editor.putString(KEY_UNIFIEDPUSH_AUTH, AUTH) }

        migratePlaintextPushState(plain, secure, dropHistory = false)

        assertEquals(AUTH, secure.values.value[KEY_UNIFIEDPUSH_AUTH])
        assertEquals("https://up.example/topic", secure.values.value[KEY_UNIFIEDPUSH_ENDPOINT])
        assertFalse(plaintextBytes().contains(AUTH))
    }

    /** Hostile Location Protection keeps history off disk, so the old copy is dropped, not moved. */
    @Test
    fun dropsRatherThanMovesHistoryUnderHostileLocationProtection(): Unit = runBlocking {
        seedPlaintext(withFlag = true)

        migratePlaintextPushState(plain, secure, dropHistory = true)

        assertNull(secure.values.value[KEY_HISTORY_JSON])
        assertEquals(AUTH, secure.values.value[KEY_UNIFIEDPUSH_AUTH])
        assertFalse(plaintextBytes().contains("Secret Subject"))
    }

    private companion object {
        const val AUTH = "auth-secret-0123456789"
        const val HISTORY = """[{"messageId":"m1","senderName":"Sender","emailSubject":"Secret Subject"}]"""
    }
}

/** In-memory [SharedPreferences]; only what [SecurePushState] touches. */
private class MapPrefs : SharedPreferences {
    private val map = mutableMapOf<String, Any?>()

    override fun getAll(): Map<String, *> = map.toMap()
    override fun getString(key: String, defValue: String?) = map[key] as String? ?: defValue
    override fun getStringSet(key: String, defValues: MutableSet<String>?) = defValues
    override fun getInt(key: String, defValue: Int) = defValue
    override fun getLong(key: String, defValue: Long) = defValue
    override fun getFloat(key: String, defValue: Float) = defValue
    override fun getBoolean(key: String, defValue: Boolean) = defValue
    override fun contains(key: String) = key in map
    override fun registerOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = Unit
    override fun unregisterOnSharedPreferenceChangeListener(l: SharedPreferences.OnSharedPreferenceChangeListener) = Unit

    override fun edit(): SharedPreferences.Editor = object : SharedPreferences.Editor {
        val puts = mutableMapOf<String, String>()
        val removes = mutableSetOf<String>()
        var clear = false
        override fun putString(key: String, value: String?) = apply { if (value == null) removes += key else puts[key] = value }
        override fun putStringSet(key: String, values: MutableSet<String>?) = this
        override fun putInt(key: String, value: Int) = this
        override fun putLong(key: String, value: Long) = this
        override fun putFloat(key: String, value: Float) = this
        override fun putBoolean(key: String, value: Boolean) = this
        override fun remove(key: String) = apply { removes += key }
        override fun clear() = apply { clear = true }
        override fun commit(): Boolean {
            if (clear) map.clear()
            removes.forEach { map.remove(it) }
            map.putAll(puts)
            return true
        }
        override fun apply() { commit() }
    }
}
