package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith

/** The endpoint is now stored before pairing, so unpairing must still be what removes it. */
@RunWith(AndroidJUnit4::class)
class UnifiedPushEndpointClearTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun unpairingClearsAnEndpointStoredBeforePairing(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.updateUnifiedPushRegistration("https://ntfy.example/up-topic", "p256dh", "auth")
        assertEquals("precondition", "https://ntfy.example/up-topic", repo.state.first().unifiedPushEndpoint)

        repo.clearPairing()

        val state = repo.state.first()
        assertNull(state.unifiedPushEndpoint)
        assertNull(state.unifiedPushP256dh)
        assertNull(state.unifiedPushAuth)
    }

    /** An endpoint callback captured before an unpair, released after it, must not restore it. */
    @Test
    fun anEndpointFromAnEndedSessionIsNotStored(): Unit = runBlocking {
        val graph = PushRuntime.graph(context)
        val captured = org.kysecurity.mail.ProcessState.generation()

        graph.repository.clearPairing()
        graph.syncCoordinator.acceptUnifiedPushEndpoint("https://ntfy.example/late", "p256dh", "auth", captured)

        val state = graph.repository.state.first()
        assertNull(state.unifiedPushEndpoint)
        assertNull(state.unifiedPushP256dh)
        assertNull(state.unifiedPushAuth)
    }

    /** A revocation captured before the session ended must not clear what the next one stored;
     *  a revocation in the current session still clears it. */
    @Test
    fun aRevocationOnlyClearsItsOwnSession(): Unit = runBlocking {
        val graph = PushRuntime.graph(context)
        val stale = org.kysecurity.mail.ProcessState.generation()
        org.kysecurity.mail.ProcessState.advanceGeneration()
        val current = org.kysecurity.mail.ProcessState.generation()
        graph.syncCoordinator.acceptUnifiedPushEndpoint("https://ntfy.example/new", "p256dh", "auth", current)

        graph.syncCoordinator.forgetUnifiedPushEndpoint(stale)
        assertEquals("https://ntfy.example/new", graph.repository.state.first().unifiedPushEndpoint)

        graph.syncCoordinator.forgetUnifiedPushEndpoint(current)
        assertNull(graph.repository.state.first().unifiedPushEndpoint)
    }
}
