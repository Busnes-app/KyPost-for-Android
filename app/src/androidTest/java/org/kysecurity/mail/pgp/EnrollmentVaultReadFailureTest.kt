package org.kysecurity.mail.pgp

import android.content.Intent
import android.content.SharedPreferences
import android.util.Base64
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.security.EncryptedStoreUnavailableException

/** Both tests exercise the legacy preference record: the file record has no lazy store to fail. */
@RunWith(AndroidJUnit4::class)
class EnrollmentVaultReadFailureTest {
    private val context = InstrumentationRegistry.getInstrumentation().targetContext
    private val vault = EnrollmentVault(context)

    @After fun cleanup() { vault.destroy(); EnrollmentSession.clear() }

    @Test
    fun transientStorageFailureIsFailedAtTheAndroidBoundaryAndRetainsTheRecoverableBlob() {
        vault.destroy()
        assertTrue("the emulator requires a secure lock screen", vault.ensureKey())
        val historical = ByteArray(48) { 9 }
        val field = prefsDelegateField()
        @Suppress("UNCHECKED_CAST")
        val original = field.get(vault) as Lazy<SharedPreferences>
        writeLegacy(original.value, ByteArray(12) { 7 }, historical)
        val unavailable = AtomicBoolean(true)
        field.set(vault, lazy {
            if (unavailable.get()) throw EncryptedStoreUnavailableException(
                EnrollmentVault.PREFS_FILE, IllegalStateException("transient test failure"),
            )
            original.value
        })
        try {
            assertTrue(runCatching { vault.stored() }.exceptionOrNull() is EncryptedStoreUnavailableException)
            // The alias is gone (a removed lock screen), and the record it sealed cannot be cleared:
            // minting a key over an unclearable record would make the probe lie.
            KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.deleteEntry(EnrollmentVault.ALIAS)
            assertFalse("an unreadable store must not admit a fresh key", vault.ensureKey())
            assertFalse(KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.containsAlias(EnrollmentVault.ALIAS))
            ActivityScenario.launch<DeviceEnrollmentActivity>(Intent(context, DeviceEnrollmentActivity::class.java)).use { scenario ->
                val opener = AtomicReference<AndroidVaultOpener>()
                scenario.onActivity { opener.set(AndroidVaultOpener(it) { vault }) }
                assertTrue(runBlocking { opener.get().open() } is OpenOutcome.Failed)
                assertFalse(opener.get().hasPendingPromptForTest())
            }
        } finally {
            unavailable.set(false)
        }
        assertArrayEquals(historical, vault.stored()!!.second)
        assertTrue(vault.hasBlob())
    }

    @Test
    fun onlyACompletelyAbsentRecordReadsAsNotEnrolled() {
        vault.destroy()
        @Suppress("UNCHECKED_CAST")
        val prefs = (prefsDelegateField().get(vault) as Lazy<SharedPreferences>).value
        val oversized = "A".repeat((384 * 1024 + 16 + 2) / 3 * 4 + 4)
        for ((iv, ct) in listOf(null to "AAAA", "AAAA" to null, "" to "", "bad!" to "AAAA", "AAAA" to "AAAA", "AAAA" to oversized)) {
            prefs.edit().clear().putString("envelope_iv", iv).putString("envelope_ct", ct).commit()
            assertTrue("partial or corrupt records must fail: $iv / ${ct?.take(8)}", runCatching { vault.stored() }.isFailure)
        }
        prefs.edit().clear().commit()
        assertNull(vault.stored())
    }

    private fun prefsDelegateField() =
        EnrollmentVault::class.java.getDeclaredField("prefs\$delegate").apply { isAccessible = true }

    private fun writeLegacy(prefs: SharedPreferences, iv: ByteArray, ct: ByteArray) {
        assertTrue(
            prefs.edit()
                .putString("envelope_iv", Base64.encodeToString(iv, Base64.NO_WRAP))
                .putString("envelope_ct", Base64.encodeToString(ct, Base64.NO_WRAP))
                .commit(),
        )
    }
}
