package org.kysecurity.mail.push

import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

/** Push history and the UnifiedPush keys must be readable through the repository and nowhere
 *  in the app's data directory in the clear. */
@RunWith(AndroidJUnit4::class)
class PushStateAtRestTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @After
    fun clear(): Unit = runBlocking { PushRuntime.graph(context).repository.clearPairing() }

    @Test
    fun historyAndUnifiedPushKeysAreNotStoredInTheClear(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.appendPayload(
            PushPayload(
                messageId = "at-rest-1", senderName = SENDER, emailSubject = SUBJECT,
                keywords = emptyList(), receivedAtEpochMs = 1L,
            ),
        )
        repo.updateUnifiedPushRegistration("https://ntfy.example/at-rest", "p256dh-at-rest", AUTH)

        val state = repo.state.first()
        assertEquals("precondition: history is stored", SUBJECT, state.history.first().emailSubject)
        assertEquals("precondition: auth is stored", AUTH, state.unifiedPushAuth)
        assertEquals("plaintext push state on disk", emptyList<String>(), plaintextLeaks())
    }

    /** An install upgraded from a build that kept these in `push_state` keeps its registration. */
    @Test
    fun valuesFromThePlaintextStoreSurviveTheUpgradeAndLeaveIt(): Unit = runBlocking {
        context.pushDataStore.edit {
            it[stringPreferencesKey("unifiedpush_endpoint")] = "https://ntfy.example/at-rest"
            it[stringPreferencesKey("unifiedpush_p256dh")] = "p256dh-at-rest"
            it[stringPreferencesKey("unifiedpush_auth")] = AUTH
        }
        PushRuntime.invalidate()

        val state = PushRuntime.graph(context).repository.state.first()

        assertEquals("https://ntfy.example/at-rest", state.unifiedPushEndpoint)
        assertEquals(AUTH, state.unifiedPushAuth)
        assertEquals("plaintext push state on disk", emptyList<String>(), plaintextLeaks())
    }

    private fun plaintextLeaks(): List<String> = context.dataDir.walkTopDown()
        .filter { it.isFile }
        .filter { file ->
            val text = file.readBytes().toString(Charsets.ISO_8859_1)
            listOf(SENDER, SUBJECT, AUTH).any { it in text }
        }
        .map { it.relativeTo(context.dataDir).path }
        .toList()

    private companion object {
        const val SENDER = "AtRest Sender 7f3a"
        const val SUBJECT = "AtRest Subject 7f3a"
        const val AUTH = "at-rest-auth-7f3a"
    }
}
