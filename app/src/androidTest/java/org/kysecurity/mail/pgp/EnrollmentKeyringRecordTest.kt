package org.kysecurity.mail.pgp

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
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

    // The teardown marker survives destroy() by design and an earlier class's teardown leaves it
    // behind, so this class's isolation clears it explicitly.
    @Before fun clean() { vault.destroy(); vault.clearTeardownReport() }
    @After fun cleanup() { vault.destroy(); vault.clearTeardownReport() }

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

    /** The instrumentation copy of the shared fixture must not drift from the pinned one. */
    @Test
    fun theFixtureCopyIsTheServersBytes() {
        val bytes = requireNotNull(javaClass.classLoader!!.getResourceAsStream("kypost-server/pgp-keyring-v1.json")).use { it.readBytes() }
        val digest = java.security.MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        assertEquals("bba7d8fde4206be91e57a4953b3b56ff915ecb24f9a0f581b7098bdc6dfcb7cc", digest)
    }

    /** Enrolled for this device's own reading and signing, and nothing the legacy report may claim. */
    @Test
    fun aKeyringRecordProbesAsEnrolledLocallyOnly() {
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 }, VaultRecordKind.KEYRING)

        val status = probeEnrollment(vault)

        assertEquals(EnrollmentStatus.ENROLLED_KEYRING, status)
        assertTrue(status.isEnrolled())
        assertNull("no stored acknowledgement: nothing may be reported", enrollmentReportFor(status, vault.keyringAck()))
    }

    /** The values the worker acknowledges live beside the record and die with it: a record
     *  replaced or destroyed must not leave a stale acknowledgement for a ring no longer held. */
    @Test
    fun theAcknowledgementIsStoredWithTheRecordAndClearedWithIt() {
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        val ack = EnrollmentReport.Keyring(materialGeneration = 2L, fingerprint = "5F117951610CAF01500FA059CDE63F0EBEC934A2")

        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 }, VaultRecordKind.KEYRING)
        assertNull("a bare store carries no acknowledgement", vault.keyringAck())
        assertTrue(vault.storeKeyringAck(ack))
        assertEquals(ack, vault.keyringAck())
        assertEquals(ack, enrollmentReportFor(probeEnrollment(vault), vault.keyringAck()))

        vault.store(ByteArray(12) { 8 }, ByteArray(48) { 9 }, VaultRecordKind.LEGACY_ARMOR)
        assertNull("replacing the record drops the acknowledgement", vault.keyringAck())

        vault.storeKeyringAck(ack)
        assertTrue(vault.destroy().isEmpty())
        assertNull("destroy removes it", vault.keyringAck())
    }

    /** A deliberate teardown is the one thing that may tell the server "not enrolled"; the marker
     *  survives until the worker has said it, and a new record supersedes it. */
    @Test
    fun theTeardownMarkerOutlivesDestroyAndDiesWithANewRecord() {
        assertTrue("the emulator needs a secure lock screen", vault.ensureKey())
        assertFalse(vault.teardownReportPending())

        EnrollmentTeardown.destroy(context)
        assertTrue("set by the teardown, after destroy cleared the store", vault.teardownReportPending())

        // The next ceremony regenerates the vault key before it seals anything; a seal the user
        // then cancels must not have silently dropped the pending "not enrolled".
        assertTrue(vault.ensureKey())
        assertTrue("regenerating the key keeps the marker", vault.teardownReportPending())
        assertTrue(vault.destroy().isEmpty())
        assertTrue("destroy keeps the marker: the teardown sets it after destroy", vault.teardownReportPending())

        assertTrue(vault.ensureKey())
        vault.store(ByteArray(12) { 7 }, ByteArray(48) { 9 }, VaultRecordKind.KEYRING)
        assertFalse("a new record is a new enrollment", vault.teardownReportPending())

        EnrollmentTeardown.destroy(context)
        assertTrue(vault.clearTeardownReport())
        assertFalse(vault.teardownReportPending())
    }
}
