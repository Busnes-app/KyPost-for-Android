package org.kysecurity.mail.push

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
import org.kysecurity.mail.testing.MapPrefs
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
