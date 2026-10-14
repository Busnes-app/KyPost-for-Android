package org.kysecurity.mail.security

import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.data.DataRuntime
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.PushPayload
import org.kysecurity.mail.push.PushRuntime
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class SecurityWipeTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    private val pairing = PairingData(
        subscriberId = "sub", serverUrl = "https://example.com",
        registrationUrl = "https://example.com/register", pairingToken = "token",
        deviceId = "device", deviceSecret = "secret", pairedAtEpochMs = 1L,
    )

    /** The resume counter is deliberately sticky in production, so reset it between tests. */
    @org.junit.Before
    fun resetWipeState() {
        context.getSharedPreferences("org.kysecurity.mail.wipe_state", android.content.Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun wipeAndResetApp_clearsPinPairingAndLockState() = runBlocking {
        val appLockStore = AppLockStore(context)
        appLockStore.setPin("482913".toCharArray())
        appLockStore.enableLock()

        PushRuntime.graph(context).securePairingStore.savePairing(pairing, gateEnabled = false)

        // Room only creates the database file lazily on first access, so force it into existence
        // here — otherwise the post-wipe "file doesn't exist" assertion below would be trivially
        // true even if wipeAndResetApp never deleted anything.
        DataRuntime.graph(context).database.openHelper.writableDatabase
        val dbFile = context.getDatabasePath("kypost_mail.db")
        assertTrue(dbFile.exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(AppLockStore(context).isLockEnabled())
        assertFalse(AppLockStore(context).verifyPin("482913".toCharArray()))
        assertNull(PushRuntime.graph(context).securePairingStore.pairing.value)
        assertFalse(dbFile.exists())
    }

    /**
     * Every EncryptedSharedPreferences file in this app is sealed under ONE AndroidKeyStore alias.
     * The wipe destroyed `kypost_credential_pepper` and `kypost_pin_pepper` — because "an alias
     * outliving a wipe is a durable, attributable artefact on a device the user was told is clean"
     * — and left behind the key that actually opens a recovered prefs blob.
     *
     * Deleted files on flash are frequently recoverable; that is the entire reason DatabaseKey
     * encrypts the SQLCipher passphrase rather than storing it plainly. Recovered blob plus live
     * master key equals the passphrase, so this alias is the difference between a wipe and a
     * delay.
     */
    @Test
    fun wipeAndResetApp_destroysTheAndroidxMasterKey() = runBlocking {
        // Force every encrypted store into existence, which mints the master key if it is absent.
        AppLockStore(context).setPin("482913".toCharArray())
        PushRuntime.graph(context).securePairingStore.savePairing(pairing, gateEnabled = false)
        DatabaseKey.passphrase(context)

        assertTrue(
            "precondition: the master key must exist, or this test proves nothing",
            keystoreAliasExists(ENCRYPTED_PREFS_MASTER_KEY_ALIAS),
        )

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(
            "the androidx security master key must not outlive the wipe",
            keystoreAliasExists(ENCRYPTED_PREFS_MASTER_KEY_ALIAS),
        )
    }

    /**
     * The step has to run AFTER the network phase, and this is the case that proves it: the
     * deregister ends in clearPairing(), which WRITES to an encrypted store and so recreates both
     * the file and the alias. A master-key deletion placed next to `credentialPeppers` is silently
     * undone on every wipe that reaches the relay — which is every wipe on a connected device.
     */
    @Test
    fun wipeAndResetApp_leavesNoEncryptedPrefsFileBehindEither() = runBlocking {
        PushRuntime.graph(context).securePairingStore.savePairing(pairing, gateEnabled = false)
        AppLockStore(context).setPin("482913".toCharArray())

        SecurityWipe.wipeAndResetApp(context)

        val sharedPrefsDir = File(context.dataDir, "shared_prefs")
        val survivors = sharedPrefsDir.listFiles { file -> file.name.endsWith(".xml") }
            .orEmpty()
            .map { it.name.removeSuffix(".xml") }

        // Asserted as a SUBSET, not as "the directory is empty". Emptiness is not the contract and
        // asserting it deleted the downloaded-attachment ledger, which is the only record of
        // plaintext that escaped the sandbox — see PREFS_NAMES_RETAINED_FINAL. What must hold is
        // that destruction still owed, or the posture the wipe deliberately re-asserts, may stay,
        // and nothing else. The hostile-location file is one boolean plus its MAC, no secret, and
        // the wipe rewrites it on purpose so protection survives its own destruction.
        val mayOutliveAWipe = setOf(
            "org.kysecurity.mail.wipe_state",
            "org.kysecurity.mail.downloaded_attachments",
            HostileLocationSettings.PREFS_NAME,
        )
        assertTrue(
            "only destruction still owed may outlive a wipe, but shared_prefs held $survivors",
            mayOutliveAWipe.containsAll(survivors),
        )
        // Named explicitly as well as covered by the subset above: these are the encrypted
        // stores, and a new one added without being swept is the regression that matters.
        listOf("push_pairing_secure", "push_state_secure", "app_lock_secure", "db_key_secure", "device_envelope_secure")
            .forEach { assertFalse("$it must not survive a wipe", it in survivors) }
    }

    private fun keystoreAliasExists(alias: String): Boolean =
        java.security.KeyStore.getInstance("AndroidKeyStore")
            .apply { load(null) }
            .containsAlias(alias)

    /** Push history holds sender names and subjects; a wipe cannot leave either store behind. */
    @Test
    fun wipeAndResetApp_removesPushHistoryFromDisk() = runBlocking {
        val repository = PushRuntime.graph(context).repository
        repository.savePairing(pairing)
        repository.appendPayload(
            PushPayload(
                messageId = "msg-1",
                senderName = "Confidential Sender",
                emailSubject = "Confidential Subject",
                keywords = listOf("legal"),
                receivedAtEpochMs = 1L,
            ),
        )

        val historyFile = File(File(context.dataDir, "shared_prefs"), "push_state_secure.xml")
        assertTrue("push_state_secure should exist before the wipe", historyFile.exists())

        SecurityWipe.wipeAndResetApp(context)

        assertFalse("push_state_secure must not survive a wipe", historyFile.exists())
        assertFalse(
            "push_state must not survive a wipe",
            File(context.filesDir, "datastore/push_state.preferences_pb").exists(),
        )
        PushRuntime.invalidate()
        assertTrue(PushRuntime.graph(context).repository.state.first().history.isEmpty())
    }

    @Test
    fun wipeAndResetApp_removesEveryOwnedPreferencesFile() = runBlocking {
        val prefsNames = listOf(
            "org.kysecurity.mail.hostile_location_settings",
            "org.kysecurity.mail.device_contacts",
            "org.kysecurity.mail.keyword_settings",
            "org.kysecurity.mail.settings",
        )
        prefsNames.forEach { name ->
            context.getSharedPreferences(name, android.content.Context.MODE_PRIVATE)
                .edit().putString("marker", "present").commit()
        }

        SecurityWipe.wipeAndResetApp(context)

        prefsNames.forEach { name ->
            assertNull(
                "$name should be gone after a wipe",
                context.getSharedPreferences(name, android.content.Context.MODE_PRIVATE)
                    .getString("marker", null),
            )
        }
    }

    @Test
    fun closeAndDeleteDatabase_leavesTheGraphUsable() = runBlocking {
        // The old contract said callers MUST restart the process afterward or the singleton would
        // keep handing out the closed database. Invalidating the holder makes that a property of
        // the code rather than a doc comment.
        DataRuntime.graph(context).database.openHelper.writableDatabase

        SecurityWipe.closeAndDeleteDatabase(context)

        val rebuilt = DataRuntime.graph(context).database
        assertTrue("DataRuntime should hand out a fresh, open database", rebuilt.openHelper.writableDatabase.isOpen)
    }

    /** Provoked through shared_prefs: "cannot enumerate what to delete" must not read as Complete. */
    @Test
    fun wipeAndResetApp_reportsIncomplete_whenAStepFails() = runBlocking {
        val sharedPrefsDir = File(context.dataDir, "shared_prefs")
        // Make the directory unlistable. On a device where the test process can't chmod its own
        // data dir this is a no-op and the assertion below would be vacuous, so skip rather than
        // pass for the wrong reason.
        val couldBlock = sharedPrefsDir.exists() && sharedPrefsDir.setReadable(false, false)
        org.junit.Assume.assumeTrue("Could not make shared_prefs unreadable on this device", couldBlock)
        try {
            val result = SecurityWipe.wipeAndResetApp(context)
            assertTrue("Expected Incomplete, got $result", result is WipeResult.Incomplete)
            assertTrue((result as WipeResult.Incomplete).failedSteps.contains("sharedPrefs"))
            // And the marker survives, so the next launch resumes it.
            assertTrue(SecurityWipe.wipeInterrupted(context))
        } finally {
            sharedPrefsDir.setReadable(true, false)
        }
    }

    /** Stopping the retries and forgetting the failure are separate; both halves are asserted. */
    @Test
    fun anIncompleteWipe_stopsResumingAfterTheCeiling_butStaysOnRecord() = runBlocking {
        val sharedPrefsDir = File(context.dataDir, "shared_prefs")
        val couldBlock = sharedPrefsDir.exists() && sharedPrefsDir.setReadable(false, false)
        org.junit.Assume.assumeTrue("Could not make shared_prefs unreadable on this device", couldBlock)
        try {
            var lastResult: WipeResult = WipeResult.Complete
            repeat(6) { lastResult = SecurityWipe.wipeAndResetApp(context) }
            // Still honestly reported as incomplete...
            assertTrue(lastResult is WipeResult.Incomplete)
            // ...no longer scheduled to run again at every launch...
            assertTrue(
                "The app must have stopped resuming the wipe by itself",
                SecurityWipe.abandonedWipe(context) != null,
            )
            // ...and still on record, because the data it could not delete is still here.
            assertTrue(
                "The marker must outlive the retries; clearing it erases the evidence",
                SecurityWipe.wipeInterrupted(context),
            )
        } finally {
            sharedPrefsDir.setReadable(true, false)
        }
    }

    /** The connector DB holds the WebPush private key; its deletion must not sit behind the network. */
    @Test
    fun wipeAndResetApp_removesTheUnifiedPushConnectorStore_evenWithNoReachableServer() = runBlocking {
        // Stand in for the connector's own database, which lives in this app's sandbox.
        context.openOrCreateDatabase("unifiedpush-connector", android.content.Context.MODE_PRIVATE, null).use {
            it.execSQL("CREATE TABLE IF NOT EXISTS webpush_keys (secret TEXT)")
            it.execSQL("INSERT INTO webpush_keys VALUES ('ecdh-private-key')")
        }
        assertTrue(context.databaseList().contains("unifiedpush-connector"))

        PushRuntime.graph(context).repository.savePairing(
            pairing.copy(serverUrl = "https://127.0.0.1:1", registrationUrl = "https://127.0.0.1:1/register"),
        )

        SecurityWipe.wipeAndResetApp(context)

        assertFalse(
            "The WebPush ECDH private key survived the wipe",
            context.databaseList().contains("unifiedpush-connector"),
        )
    }

}
