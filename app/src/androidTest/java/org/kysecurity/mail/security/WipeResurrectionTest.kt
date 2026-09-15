package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class WipeResurrectionTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://127.0.0.1:1",
        registrationUrl = "https://127.0.0.1:1/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    private fun dbFile() = context.getDatabasePath("kypost_mail.db")
    private fun pushStateFile() = File(context.filesDir, "datastore/push_state.preferences_pb")
    private fun hostilePrefsFile() =
        File(File(context.dataDir, "shared_prefs"), "org.kysecurity.mail.hostile_location_settings.xml")
    private fun ledgerFile() =
        File(File(context.dataDir, "shared_prefs"), "org.kysecurity.mail.downloaded_attachments.xml")

    /** isEnabled() alone proves nothing here: with the marker file gone, readState() takes the
     *  `storedMac == null` branch and fails towards ENABLED as tampering, so the posture reads
     *  restored while the restore step's write is in fact deleted. This asserts the write is on
     *  disk and authentic, which is exactly the negation of that branch. */
    private fun assertProtectionRestoredOnDisk() {
        assertTrue(
            "the restored marker file must survive the wipe's final sweep",
            hostilePrefsFile().exists(),
        )
        val prefs = context.getSharedPreferences(
            "org.kysecurity.mail.hostile_location_settings", android.content.Context.MODE_PRIVATE,
        )
        assertTrue("the restored posture must be stored as enabled", prefs.getBoolean("enabled", false))
        val storedMac = prefs.getString("enabled_mac", null)
        assertNotNull("a missing MAC is the fail-open tamper branch, not a persisted posture", storedMac)
        assertEquals(
            "the MAC must authenticate the stored value, not merely exist",
            android.util.Base64.encodeToString(
                KeystoreHlpKey.mix(byteArrayOf(1)), android.util.Base64.NO_WRAP,
            ),
            storedMac,
        )
        assertEquals(
            "and the read must land on the honoured-value branch",
            HostileLocationState.ENABLED,
            HostileLocationSettings(context).state(),
        )
    }

    @Before
    fun clean() {
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
        // The attachment ledger is deliberately retained across a wipe now, so an undeletable entry
        // left by one test would otherwise fail the next one's sweep.
        context.deleteSharedPreferences("org.kysecurity.mail.downloaded_attachments")
        HostileLocationSettings(context).setEnabled(false)
        DataRuntime.invalidate()
        PushRuntime.invalidate()
        SecurityRuntime.invalidate()
    }

    /** Without this the posture leaks into whatever class runs next: nothing in a wipe destroys the
     *  keystore alias, so a surviving alias with no marker reads as ENABLED and the next class's
     *  wipe restores and retains the file. */
    @After
    fun disableProtection() {
        HostileLocationSettings(context).setEnabled(false)
    }

    /** purgeAccountScopedData must peek the graph, not construct one after the delete step. */
    @Test
    fun wipe_doesNotRecreateTheDatabaseFileItDeleted(): Unit = runBlocking {
        DataRuntime.graph(context).database.openHelper.writableDatabase
        assertTrue("precondition: db exists", dbFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(
            "kypost_mail.db must not be recreated by the wipe's own later steps",
            dbFile().exists(),
        )
    }

    /** The other half of that ordering: work submitted WHILE the wipe runs.
     *
     *  `quiesce()` used to install a fresh pool on its way out, so the lane it was supposed to shut
     *  reopened immediately — a mark-read or a notification tap landing mid-wipe got a live thread,
     *  a rebuilt [DataRuntime] graph, and a recreated `kypost_mail.db` behind a wipe that had
     *  already reported the file deleted. The file is what this asserts.
     *
     *  Deliberately NOT asserting that no task ran at all: work submitted in the moment before
     *  [SecurityWipe.wipeAndResetApp] reaches its `quiesce()` is legitimate, and the wipe interrupts
     *  it, waits for it, and deletes whatever it opened. That version of this test failed on API 34
     *  and 36 and passed on 31 — pure timing on a window the product never promised to close. The
     *  executor's real contract, that nothing starts after `quiesce()` returns, is pinned
     *  deterministically by `MailBackgroundExecutorTest`. */
    @Test
    fun wipe_refusesMailWorkSubmittedWhileItRuns(): Unit = runBlocking {
        DataRuntime.graph(context).database.openHelper.writableDatabase
        assertTrue("precondition: db exists", dbFile().exists())

        val wipeRunning = java.util.concurrent.atomic.AtomicBoolean(false)
        val stop = java.util.concurrent.atomic.AtomicBoolean(false)
        val submitted = java.util.concurrent.atomic.AtomicInteger(0)
        val submitter = Thread {
            while (!stop.get()) {
                submitted.incrementAndGet()
                org.kysecurity.mail.MailBackgroundExecutor.submit {
                    // Scoped to the wipe's window so the tail of this thread, running after the
                    // wipe has legitimately restored the pool, cannot recreate the file itself.
                    if (!wipeRunning.get()) return@submit
                    // The resurrection primitive, called directly: building a data graph opens —
                    // and therefore creates — the database file the wipe has just deleted.
                    DataRuntime.graph(context).database.openHelper.writableDatabase
                }
                Thread.sleep(1)
            }
        }.apply { start() }

        try {
            wipeRunning.set(true)
            SecurityWipe.wipeAndResetApp(context)
        } finally {
            wipeRunning.set(false)
            stop.set(true)
            submitter.join(5_000)
        }

        // Or the assertion below passes because nothing was ever aimed at the wipe.
        assertTrue("precondition: the hammer submitted work", submitted.get() > 0)
        assertFalse("kypost_mail.db must not be recreated by work racing the wipe", dbFile().exists())
    }

    /** Under HLP the resurrected graph was disk-backed, since the flag file was already deleted. */
    @Test
    fun wipe_underHostileLocation_leavesNoDatabaseOnDisk(): Unit = runBlocking {
        HostileLocationSettings(context).setEnabled(true)
        DataRuntime.invalidate()
        SecurityRuntime.invalidate()
        PushRuntime.invalidate()
        context.deleteDatabase("kypost_mail.db")
        // In-memory graph, as the feature promises.
        DataRuntime.graph(context).database.openHelper.writableDatabase
        assertFalse("precondition: no db file under protection", dbFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertTrue("protection flag restored", HostileLocationSettings(context).isEnabled())
        assertProtectionRestoredOnDisk()
        assertFalse(
            "no disk-backed kypost_mail.db may exist after a wipe under Hostile Location Protection",
            dbFile().exists(),
        )
    }

    /** `restoreHostileLocationProtection` was dead code: the LAST sweep, `androidxMasterKey`,
     *  deleted the file the step had just written, and the posture only kept reading ENABLED
     *  because a missing marker fails towards tampering — logging a permanent false tamper alarm
     *  on every later read. This fails on that ordering: the file, the value and its MAC must all
     *  be there afterwards. */
    @Test
    fun wipe_persistsTheRestoredHostileLocationFlag(): Unit = runBlocking {
        HostileLocationSettings(context).setEnabled(true)
        assertTrue("precondition: the marker was written", hostilePrefsFile().exists())

        val result = SecurityWipe.wipeAndResetApp(context)

        assertTrue("the wipe must still complete, got $result", result is WipeResult.Complete)
        assertProtectionRestoredOnDisk()
    }

    /** The posture is recorded in wipe_state, since the resumed run cannot re-read the deleted file. */
    @Test
    fun resumedWipe_restoresHostileLocationProtection(): Unit = runBlocking {
        HostileLocationSettings(context).setEnabled(true)
        assertTrue(HostileLocationSettings(context).isEnabled())

        // What the first, interrupted run left behind: marker set with the posture recorded, and the
        // prefs file already deleted.
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit()
            .putBoolean("wipe_in_progress", true)
            .putBoolean("hostile_location_was_enabled", true)
            .putInt("wipe_attempts", 1)
            .commit()
        context.deleteSharedPreferences("org.kysecurity.mail.hostile_location_settings")
        assertFalse(hostilePrefsFile().exists())
        assertTrue(SecurityWipe.wipeInterrupted(context))

        // Cold-start resume path.
        SecurityWipe.enforceTripwire(context)

        assertTrue(
            "Hostile Location Protection must survive a resumed wipe",
            HostileLocationSettings(context).isEnabled(),
        )
    }

    /** The counter is scoped to one wipe episode: not a rolling window, not a lifetime budget. */
    @Test
    fun wipeAttemptCeiling_climbsWhileResuming_thenResetsForTheNextWipe(): Unit = runBlocking {
        val prefs = context.getSharedPreferences(
            "org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE,
        )
        val dir = File(context.dataDir, "shared_prefs")
        org.junit.Assume.assumeTrue(dir.exists() && dir.setReadable(false, false))
        try {
            val seen = mutableListOf<Int>()
            repeat(5) {
                SecurityWipe.wipeAndResetApp(context)
                seen += prefs.getInt("wipe_attempts", 0)
            }
            assertEquals(
                "the count must climb while resuming ONE wipe, then start over for the next one",
                listOf(1, 2, 3, 1, 2),
                seen,
            )
        } finally {
            dir.setReadable(true, false)
        }
    }

    /** willRetry is what stops the UI promising a retry on the run that gave up. */
    @Test
    fun pastTheCeiling_theResultReportsThatNoRetryIsComing(): Unit = runBlocking {
        val dir = File(context.dataDir, "shared_prefs")
        org.junit.Assume.assumeTrue(dir.exists() && dir.setReadable(false, false))
        try {
            // Three attempts is the whole budget for one episode: 1, 2, then 3 which gives up.
            // A fourth call would be a NEW episode and would correctly promise a retry again.
            var last: WipeResult? = null
            repeat(3) { last = SecurityWipe.wipeAndResetApp(context) }
            val result = last
            assertTrue("a failing wipe must report Incomplete", result is WipeResult.Incomplete)
            assertFalse(
                "past MAX_WIPE_RESUMES the user must not be promised a retry",
                (result as WipeResult.Incomplete).willRetry,
            )
        } finally {
            dir.setReadable(true, false)
        }
    }

    /** Giving up on retries must not forget that deletion failed; the marker and steps persist. */
    @Test
    fun pastTheCeiling_theIncompleteStateIsPermanentAndNotForgotten(): Unit = runBlocking {
        val dir = File(context.dataDir, "shared_prefs")
        org.junit.Assume.assumeTrue(dir.exists() && dir.setReadable(false, false))
        try {
            repeat(3) { SecurityWipe.wipeAndResetApp(context) }

            assertTrue(
                "the marker must survive: deletion failed, so the app has to keep knowing that",
                SecurityWipe.wipeInterrupted(context),
            )
            val abandoned = SecurityWipe.abandonedWipe(context)
            assertTrue("the abandoned state must name what was left behind", abandoned != null)
            assertTrue(
                "the failed steps must be recorded, got ${abandoned?.failedSteps}",
                abandoned!!.failedSteps.contains("sharedPrefs"),
            )
        } finally {
            dir.setReadable(true, false)
        }

        // Readable again: a resume WOULD now succeed. enforceTripwire must still refuse to run one
        // and must still report the terminal state, or "permanent" is only true while the original
        // failure persists — and the user gets a clean app back the moment the file unlocks.
        val verdict = SecurityWipe.enforceTripwire(context)
        assertTrue("the terminal verdict must be reported on every later launch", verdict is WipeResult.Incomplete)
        assertFalse(
            "and it must never promise a retry",
            (verdict as WipeResult.Incomplete).willRetry,
        )
    }

    /** A row in shared storage that this app cannot delete must NOT fail the wipe.
     *
     *  It used to be a `step`, so an undeletable Downloads row failed the wipe on every resume
     *  until MAX_WIPE_RESUMES marked it abandoned and blocked the app permanently — over a file
     *  the user can delete in ten seconds, in a provider this app does not own. The wipe now
     *  completes, keeps the ledger so a later sweep can retry, and reports the count. */
    @Test
    fun wipe_completesButReportsAttachmentsItCouldNotRemove(): Unit = runBlocking {
        DownloadedAttachmentLedger.record(
            context,
            android.net.Uri.parse("content://org.kysecurity.mail.no.such.provider/1"),
        )

        val result = SecurityWipe.wipeAndResetApp(context)

        assertTrue(
            "an unreachable shared-storage row must not fail the wipe, got $result",
            result is WipeResult.Complete,
        )
        assertTrue(
            "and the user must be told, or the wipe notice is a false claim",
            SecurityWipe.strandedDownloadsPending(context) > 0,
        )
        assertTrue(
            "the ledger must survive so a later sweep has work",
            ledgerFile().exists(),
        )
        assertTrue(
            "the undeleted URI must still be recorded",
            context.getSharedPreferences("org.kysecurity.mail.downloaded_attachments", android.content.Context.MODE_PRIVATE)
                .getStringSet("uris", emptySet()).orEmpty().isNotEmpty(),
        )

        SecurityWipe.acknowledgeStrandedDownloads(context)
        assertEquals(
            "acknowledging must clear it, or the notice repeats forever",
            0,
            SecurityWipe.strandedDownloadsPending(context),
        )
    }

    /** ...and once the step genuinely succeeds, the ledger goes: retained is not the same as kept
     *  forever, and a stale file would make the next wipe re-try work that is already done. */
    @Test
    fun aSuccessfulAttachmentSweepRemovesTheLedger(): Unit = runBlocking {
        // A media URI for a row that does not exist: the delete affects 0 rows and the re-query
        // finds nothing, so it is correctly treated as already gone.
        DownloadedAttachmentLedger.record(
            context,
            android.net.Uri.parse("content://media/external/downloads/999999999"),
        )
        // record() uses commit(), so the file is on disk by the time it returns — no await. That
        // durability is the point: the row has to outlive a process death that happens between
        // saving an attachment and the wipe that is supposed to delete it.
        assertTrue("precondition: ledger written synchronously", ledgerFile().exists())

        DownloadedAttachmentLedger.deleteAll(context)

        assertFalse("a completed sweep must not leave its ledger behind", ledgerFile().exists())
    }

    /** Through the real wipeAndResetApp: ordering is the risk, sharedPrefs sweeps after this step. */
    @Test
    fun wipe_destroysTheDeviceEnrollment(): Unit = runBlocking {
        val vault = org.kysecurity.mail.pgp.EnrollmentVault(context)
        org.kysecurity.mail.pgp.EnrollmentKeyStore.newKeyPair()
        vault.ensureKey()
        vault.store(ByteArray(12), ByteArray(48))
        assertTrue("precondition: enrollment present", vault.hasBlob())

        SecurityWipe.wipeAndResetApp(context)

        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "agreement key survived the wipe",
            ks.containsAlias(org.kysecurity.mail.pgp.EnrollmentKeyStore.ALIAS),
        )
        assertFalse(
            "vault key survived the wipe",
            ks.containsAlias(org.kysecurity.mail.pgp.EnrollmentVault.ALIAS),
        )
        assertFalse(
            "sealed envelope survived the wipe",
            org.kysecurity.mail.pgp.EnrollmentVault(context).hasBlob(),
        )
        assertFalse(
            "sealed record file survived the wipe",
            java.io.File(context.filesDir, org.kysecurity.mail.pgp.EnrollmentVault.RECORD_FILE).exists(),
        )
    }

    /** Two Keystore aliases had no teardown at all and no comment saying why, so a wipe reported
     *  Complete over `kypost_credential_pepper` and `kypost_pin_pepper` still sitting in the
     *  Keymaster blob store — a durable, attributable record that this app was installed and a
     *  PIN was configured, on a device the routine had just called clean. */
    @Test
    fun wipe_destroysTheCredentialPeppers(): Unit = runBlocking {
        KeystoreCredentialPepper.ensureExists()
        KeystorePinPepper.ensureExists()
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertTrue("precondition: peppers present", ks.containsAlias(KeystoreCredentialPepper.ALIAS))
        assertTrue("precondition: peppers present", ks.containsAlias(KeystorePinPepper.ALIAS))

        val result = SecurityWipe.wipeAndResetApp(context)

        val after = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        assertFalse(
            "credential pepper survived the wipe",
            after.containsAlias(KeystoreCredentialPepper.ALIAS),
        )
        assertFalse(
            "pin pepper survived the wipe",
            after.containsAlias(KeystorePinPepper.ALIAS),
        )
        assertTrue("and the wipe must not have reported a failure, got $result", result is WipeResult.Complete)
    }

    /** The datastore holding the last 30 sender/subject pairs must actually be gone. */
    @Test
    fun wipe_deletesThePushHistoryDatastore(): Unit = runBlocking {
        val repo = PushRuntime.graph(context).repository
        repo.savePairing(pairing)
        repo.appendPayload(
            org.kysecurity.mail.push.PushPayload(
                messageId = "m1", senderName = "Sender X", emailSubject = "Subject Y",
                keywords = listOf("legal"), receivedAtEpochMs = 1L,
            ),
        )
        assertTrue("precondition: push_state written", pushStateFile().exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse("push_state must not survive a wipe", pushStateFile().exists())
    }
}
