package org.kysecurity.mail.push

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/**
 * The stored pin set used to hold every certificate in the observed chain except its trust anchor,
 * which for the ordinary deployment meant a public CA intermediate — a pin that admits every
 * certificate that CA issues. Sets written before the leaf-only rule must therefore be REPLACED on
 * the next capture, never merged into, or the intermediate would outlive the rule that retired it.
 *
 * There is no rolling window to merge into any more: see [PushSyncCoordinator.refreshTlsPin].
 */
@RunWith(AndroidJUnit4::class)
class TlsPinNarrowingTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val host = "relay.test.invalid"

    private fun pin(seed: Byte): String =
        "sha256/" + java.util.Base64.getEncoder().encodeToString(ByteArray(32) { seed })

    @Before
    fun clearStore() {
        runBlocking { SecurePairingStore(context).clearPairing() }
        context.getSharedPreferences(TLS_PIN_TRIPWIRE_PREFS, Context.MODE_PRIVATE).edit().clear().commit()
    }

    @Test
    fun aFreshlyClearedStoreIsNotMarkedLeafOnly() {
        assertFalse(SecurePairingStore(context).tlsPinIsLeafOnly())
    }

    @Test
    fun savingAPinMarksTheStoredSetAsLeafOnly() = runBlocking {
        val store = SecurePairingStore(context)

        store.saveTlsPin(TlsPin(host, setOf(pin(1))))

        assertTrue(store.tlsPinIsLeafOnly())
        assertEquals(setOf(pin(1)), store.currentTlsPin()?.spkiSha256)
    }

    /** Narrowing is one-way and happens once. A legacy whole-chain set is REPLACED by the single
     *  observed leaf, and the marker that records it must survive the next read. */
    @Test
    fun aLegacyWholeChainSetIsReplacedByTheLeafAndStaysThatWay() = runBlocking {
        val store = SecurePairingStore(context)
        // The shape an install pinned under the old rule carries: leaf plus its issuers.
        store.saveTlsPin(TlsPin(host, setOf(pin(1), pin(2), pin(3))))

        store.saveTlsPin(TlsPin(host, setOf(pin(1))))

        assertEquals(setOf(pin(1)), store.currentTlsPin()!!.spkiSha256)
        assertTrue(SecurePairingStore(context).tlsPinIsLeafOnly())
    }

    @Test
    fun clearingThePairingAlsoClearsTheLeafOnlyMarker() = runBlocking {
        val store = SecurePairingStore(context)
        store.saveTlsPin(TlsPin(host, setOf(pin(1))))
        assertTrue(store.tlsPinIsLeafOnly())

        store.clearPairing()

        assertFalse(SecurePairingStore(context).tlsPinIsLeafOnly())
    }
}
