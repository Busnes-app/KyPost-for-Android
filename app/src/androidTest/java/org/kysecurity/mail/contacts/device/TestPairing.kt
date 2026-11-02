package org.kysecurity.mail.contacts.device

import android.content.Context
import kotlinx.coroutines.runBlocking
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime

/** The contacts disclosure names the paired server, so turning sync on needs a pairing. */
internal val TEST_SYNC_PAIRING = PairingData(
    subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
    registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
    deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
)

/** The server the disclosure names for [TEST_SYNC_PAIRING]. */
internal const val TEST_SYNC_SERVER = "https://127.0.0.1:1"

internal fun pairForSyncTest(context: Context) = runBlocking { PushRuntime.graph(context).repository.savePairing(TEST_SYNC_PAIRING) }

internal fun unpairAfterSyncTest(context: Context) {
    runBlocking { PushRuntime.graph(context).repository.clearPairing() }
}
