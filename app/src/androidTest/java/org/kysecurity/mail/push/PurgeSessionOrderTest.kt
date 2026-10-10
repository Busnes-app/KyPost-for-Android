package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.ComposeDraftCache
import org.kysecurity.mail.ProcessState

/** Work from the outgoing session must read as stale for the whole purge, not just its end. */
@RunWith(AndroidJUnit4::class)
class PurgeSessionOrderTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    @Test
    fun aCompletionDuringThePurgesDatabaseStepIsAlreadyStale(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        val token = ProcessState.generation()
        val currentAtStep = mutableMapOf<String, Boolean>()
        repo.purgeStepObserverForTest = { step -> currentAtStep[step] = ProcessState.isCurrent(token) }
        try {
            repo.clearPairing()
        } finally {
            repo.purgeStepObserverForTest = null
            ComposeDraftCache.take() // resetAll seals it; later classes need it open.
        }

        assertEquals("an old-session completion was still current", false, currentAtStep["database"])
    }

    /** Mail work submitted mid-teardown would run after the reset with the old pairing still on file. */
    @Test
    fun mailWorkSubmittedDuringTheTeardownIsHeldBack(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        var droppedAtStep: Boolean? = null
        repo.purgeStepObserverForTest = { step ->
            if (step == "database") {
                var dropped = false
                org.kysecurity.mail.MailBackgroundExecutor.submit(onDropped = { dropped = true }) {}
                droppedAtStep = dropped
            }
        }
        try {
            repo.clearPairing()
        } finally {
            repo.purgeStepObserverForTest = null
            ComposeDraftCache.take()
        }

        assertEquals("mail work was accepted while the account was torn down", true, droppedAtStep)
    }
}
