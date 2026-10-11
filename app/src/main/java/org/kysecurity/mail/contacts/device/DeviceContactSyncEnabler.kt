package org.kysecurity.mail.contacts.device

import android.Manifest
import android.content.pm.PackageManager
import android.widget.Toast
import androidx.activity.result.ActivityResultLauncher
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import org.kysecurity.mail.R
import kotlinx.coroutines.launch

class DeviceContactSyncEnabler(
    private val activity: AppCompatActivity,
    private val permissionLauncher: ActivityResultLauncher<Array<String>>,
    private val onEnabled: () -> Unit = {},
) {
    /** True when permissions had to be requested; the caller must wait for the launcher callback. */
    fun checkAndEnable(): Boolean {
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
                graph.settings.setEnabled(true)
                PendingAccountSetup.complete(DeviceContactAccount.ACCOUNT_NAME)
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
