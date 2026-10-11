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
}
