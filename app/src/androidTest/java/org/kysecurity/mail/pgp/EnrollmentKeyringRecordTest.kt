package org.kysecurity.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/** The record's format byte: written by [EnrollmentVault.store], read back by [EnrollmentVault.stored],
 *  and reported by [probeEnrollment] without ever inspecting plaintext. */
@RunWith(AndroidJUnit4::class)
class EnrollmentKeyringRecordTest {

    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val vault = EnrollmentVault(context)

    @Before fun clean() { vault.destroy() }
    @After fun cleanup() { vault.destroy() }

    @Test
    fun theKindRoundTripsAndDefaultsToLegacy() {
        assertTrue(vault.store(ByteArray(12) { 1 }, ByteArray(40) { 2 }))
        assertEquals(VaultRecordKind.LEGACY_ARMOR, EnrollmentVault(context).stored()!!.kind)

        assertTrue(vault.store(ByteArray(12) { 3 }, ByteArray(40) { 4 }, VaultRecordKind.KEYRING))
        val record = EnrollmentVault(context).stored()!!
        assertEquals(VaultRecordKind.KEYRING, record.kind)
        assertEquals(2.toByte(), File(context.filesDir, EnrollmentVault.RECORD_FILE).readBytes()[0])

        File(context.filesDir, EnrollmentVault.RECORD_FILE).writeBytes(byteArrayOf(3) + ByteArray(12) + ByteArray(16))
        assertTrue("an unknown format byte fails closed", runCatching { vault.stored() }.isFailure)
    }

    /** Enrolled for this device's own reading and signing, and nothing the legacy report may claim. */
    @Test
    fun aKeyringRecordProbesAsEnrolledLocallyOnly() {
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 }, VaultRecordKind.KEYRING)

        val status = probeEnrollment(vault)

        assertEquals(EnrollmentStatus.ENROLLED_KEYRING, status)
        assertTrue(status.isEnrolled())
        assertFalse("the v2 acknowledgement must stay false for a prepared keyring", status.legacyReportValue())
    }
}
