package org.kysecurity.mail.pgp

import android.content.Intent
import android.content.SharedPreferences
import androidx.test.core.app.ActivityScenario
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
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
        vault.store(ByteArray(12) { 7 }, historical)
        val field = EnrollmentVault::class.java.getDeclaredField("prefs\$delegate").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val original = field.get(vault) as Lazy<SharedPreferences>
        val unavailable = AtomicBoolean(true)
        field.set(vault, lazy {
            if (unavailable.get()) throw EncryptedStoreUnavailableException(
                EnrollmentVault.PREFS_FILE, IllegalStateException("transient test failure"),
            )
            original.value
        })
        try {
            assertTrue(runCatching { vault.stored() }.exceptionOrNull() is EncryptedStoreUnavailableException)
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
        vault.store(ByteArray(12), ByteArray(48))
        val field = EnrollmentVault::class.java.getDeclaredField("prefs\$delegate").apply { isAccessible = true }
        @Suppress("UNCHECKED_CAST")
        val prefs = (field.get(vault) as Lazy<SharedPreferences>).value
        for ((iv, ct) in listOf(null to "AAAA", "AAAA" to null, "" to "", "bad!" to "AAAA", "AAAA" to "AAAA")) {
            prefs.edit().clear().putString("envelope_iv", iv).putString("envelope_ct", ct).commit()
            assertTrue("partial or corrupt records must fail: $iv / $ct", runCatching { vault.stored() }.isFailure)
        }
        prefs.edit().clear().commit()
        assertNull(vault.stored())
    }
}
