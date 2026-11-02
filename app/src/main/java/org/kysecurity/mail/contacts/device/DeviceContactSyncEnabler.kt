package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.annotation.StringRes
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import org.kysecurity.mail.contacts.ContactsRuntime
import org.kysecurity.mail.showThemed
import kotlinx.coroutines.launch

class DeviceContactSyncEnabler(
    private val activity: AppCompatActivity,
    private val permissionLauncher: ActivityResultLauncher<Array<String>>,
    private val onEnabled: () -> Unit = {},
    /** The account-setup request this screen serves, or null when enabling from the menu. */
    private val setupToken: () -> Long? = { null },
) {
    /** A setup screen whose request a newer one displaced must not act on it. */
    private fun displaced(): Boolean = setupToken()?.let { !PendingAccountSetup.isCurrent(it) } == true

    /** The pairing the disclosure names, or null, with a toast, when there is none to name. */
    suspend fun pairedDestination(): String? =
        ContactsRuntime.graph(activity).repository.destination()
            ?: null.also { Toast.makeText(activity, R.string.contacts_device_sync_not_paired, Toast.LENGTH_LONG).show() }

    /** Google Play's prominent disclosure, shown on every path before contacts access is requested:
     *  what is sent, to which server ([destination], from [pairedDestination]) and why. Agree
     *  records consent for that pairing and enables, asking for the permission if needed, and
     *  passes [onContinue] whether it asked; Not now or Back asks for and records nothing. [lead]
     *  says why the dialog appeared, when the user did not ask. */
    fun askToEnable(
        destination: String,
        @StringRes lead: Int? = null,
        onDecline: () -> Unit = {},
        onContinue: (requestedPermission: Boolean) -> Unit = {},
    ): AlertDialog = AlertDialog.Builder(activity)
        .setTitle(R.string.contact_sync_intro_title)
        .setMessage(
            listOfNotNull(
                lead?.let { activity.getString(it) },
                activity.getString(R.string.contacts_access_disclosure, destination.substringBefore('\n')),
            ).joinToString("\n\n"),
        )
        .setPositiveButton(R.string.contact_sync_intro_positive) { _, _ -> agree(destination); onContinue(checkAndEnable()) }
        .setNegativeButton(R.string.contact_sync_intro_negative) { _, _ -> onDecline() }
        .setOnCancelListener { onDecline() }
        .showThemed()

    private fun agree(destination: String) = DeviceContactsRuntime.graph(activity).settings.recordConsent(destination)

    /** Withdraws consent: sync off, import choices cleared, and the KyPost account (with the
     *  contacts it put in the phone's address book) removed. Nothing more is sent until the user
     *  agrees to the disclosure again. */
    fun revoke(onRevoked: () -> Unit = {}) {
        val graph = DeviceContactsRuntime.graph(activity)
        activity.lifecycleScope.launch {
            try {
                graph.settings.clearConsentDuring {}
                DeviceContactSyncScheduler.cancelPeriodic(activity)
                graph.observer.unregister()
                graph.accountManager.removeAccount()
                Toast.makeText(activity, R.string.contacts_device_sync_disabled_toast, Toast.LENGTH_SHORT).show()
                onRevoked()
            } catch (e: kotlinx.coroutines.CancellationException) {
                // The activity went away mid-disable; swallowing it toasts a destroyed activity.
                throw e
            } catch (e: Exception) {
                Toast.makeText(activity, "Failed to disable device sync: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }

    /** True when permissions had to be requested; the caller must wait for the launcher callback. */
    private fun checkAndEnable(): Boolean {
        if (displaced()) {
            activity.finish()
            return false
        }
        // Refused, not just defaulted off: synced contacts land in the OS contacts provider, which
        // Hostile Location Protection's in-memory database does not cover.
        if (!DeviceContactsRuntime.graph(activity).syncPermitted()) {
            Toast.makeText(activity, R.string.contacts_device_sync_blocked_hostile_location, Toast.LENGTH_LONG).show()
            return false
        }

        val readContactsGranted = ContextCompat.checkSelfPermission(
            activity,
            Manifest.permission.READ_CONTACTS,
        ) == PackageManager.PERMISSION_GRANTED
        val writeContactsGranted = ContextCompat.checkSelfPermission(
            activity,
            Manifest.permission.WRITE_CONTACTS,
        ) == PackageManager.PERMISSION_GRANTED

        return if (readContactsGranted && writeContactsGranted) {
            enableAfterPermissionGrant()
            false
        } else {
            permissionLauncher.launch(
                arrayOf(
                    Manifest.permission.READ_CONTACTS,
                    Manifest.permission.WRITE_CONTACTS,
                ),
            )
            true
        }
    }

    fun enableAfterPermissionGrant() {
        if (displaced()) {
            activity.finish()
            return
        }
        val graph = DeviceContactsRuntime.graph(activity)
        if (!graph.syncPermitted()) {
            Toast.makeText(activity, R.string.contacts_device_sync_blocked_hostile_location, Toast.LENGTH_LONG).show()
            return
        }
        activity.lifecycleScope.launch {
            try {
                // Enabling over a failed account creation scheduled the periodic worker against an
                // account that does not exist, and left teardown with no account to purge rows under.
                if (!graph.accountManager.ensureAccount()) {
                    Toast.makeText(activity, R.string.contacts_device_sync_account_failed, Toast.LENGTH_LONG).show()
                    return@launch
                }
                // Rechecked after the suspension above: the request may have been displaced since.
                if (displaced()) {
                    activity.finish()
                    return@launch
                }
                // The pairing may have changed while the disclosure was open: the user agreed to
                // send contacts to the server it named, not to whichever is paired now.
                if (graph.settings.consentedDestination() != ContactsRuntime.graph(activity).repository.destination()) {
                    Toast.makeText(activity, R.string.contacts_device_sync_not_paired, Toast.LENGTH_LONG).show()
                    return@launch
                }
                graph.settings.setEnabled(true)
                setupToken()?.let { PendingAccountSetup.complete(it, DeviceContactAccount.ACCOUNT_NAME) }
                    ?: PendingAccountSetup.complete(DeviceContactAccount.ACCOUNT_NAME)
                graph.observer.register()
                DeviceContactSyncScheduler.ensurePeriodic(activity)
                graph.coordinator.syncNowAsync()
                Toast.makeText(activity, R.string.contacts_device_sync_enabled_toast, Toast.LENGTH_SHORT).show()
                onEnabled()
            } catch (e: kotlinx.coroutines.CancellationException) {
                // The activity went away mid-enable; swallowing it toasts a destroyed activity.
                throw e
            } catch (e: Exception) {
                Toast.makeText(activity, "Failed to enable device sync: ${e.message}", Toast.LENGTH_SHORT).show()
            }
        }
    }
}
