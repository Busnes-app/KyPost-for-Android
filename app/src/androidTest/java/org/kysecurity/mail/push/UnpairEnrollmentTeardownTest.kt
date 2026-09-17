package org.kysecurity.mail.push

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.pgp.EnrollmentKeyStore
import org.kysecurity.mail.pgp.EnrollmentVault
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Test
import org.junit.runner.RunWith
import java.security.KeyStore

/** Unpairing must destroy the envelope, or one account's key persists into the next session. */
@RunWith(AndroidJUnit4::class)
class UnpairEnrollmentTeardownTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    @Test
    fun clearingThePairingDestroysTheEnrollment(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        val vault = EnrollmentVault(context)
        EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        repo.clearPairing()

        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse("agreement key survived the unpair", ks.containsAlias(EnrollmentKeyStore.ALIAS))
        assertFalse("vault key survived the unpair", ks.containsAlias(EnrollmentVault.ALIAS))
        assertFalse("sealed envelope survived the unpair", EnrollmentVault(context).hasBlob())
    }

    /** The teardown marker asks the worker to tell the server "not enrolled". With the pairing
     *  gone there is no device row to correct, and a marker that survived would be sent for the
     *  next pairing's device row, making the server forget a delivery it holds for that device. */
    @Test
    fun clearingThePairingDropsTheTeardownMarker(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        val vault = EnrollmentVault(context)
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))

        repo.clearPairing()

        assertFalse("teardown marker survived the unpair", vault.teardownReportPending())
    }
}
