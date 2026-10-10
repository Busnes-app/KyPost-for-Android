package org.kysecurity.mail.contacts

import android.content.Intent
import android.os.Bundle
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.Toast
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.WorkManager
import com.google.android.material.floatingactionbutton.FloatingActionButton
import com.google.android.material.navigation.NavigationBarView
import org.kysecurity.mail.R
import org.kysecurity.mail.applyEmptyStateBackground
import org.kysecurity.mail.applyKyPostTopBar
import org.kysecurity.mail.applyPrimaryNavigationInsets
import org.kysecurity.mail.applyPrimaryNavigationTheme
import org.kysecurity.mail.applyThemeToActivity
import org.kysecurity.mail.applyTopInsetWithHeader
import org.kysecurity.mail.contacts.device.DeviceContactAccount
import org.kysecurity.mail.contacts.device.DeviceContactsRuntime
import org.kysecurity.mail.contacts.device.DeviceContactSyncEnabler
import org.kysecurity.mail.contacts.device.DeviceContactSyncScheduler
import org.kysecurity.mail.contacts.device.PendingAccountSetup
import org.kysecurity.mail.data.ContactEntity
import org.kysecurity.mail.pgp.hasPgpIdentity
import org.kysecurity.mail.setupPrimaryNavigation
import kotlinx.coroutines.launch
import org.kysecurity.mail.security.LockedActivity
import org.kysecurity.mail.security.showSecurely

class ContactsListActivity : LockedActivity() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyText: View
    private lateinit var bottomNav: NavigationBarView
    private lateinit var adapter: ContactAdapter
    private var pickMode: Boolean = false
    private var pendingScrollPosition: Int = 0
    private val contactPermissionLauncher: androidx.activity.result.ActivityResultLauncher<Array<String>> = registerForActivityResult(
        androidx.activity.result.contract.ActivityResultContracts.RequestMultiplePermissions(),
    ) { permissions ->
        val allGranted = permissions.all { it.value }
        if (!allGranted) {
            Toast.makeText(this, R.string.contacts_device_sync_permission_denied, Toast.LENGTH_SHORT).show()
            return@registerForActivityResult
        }
        syncEnabler.enableAfterPermissionGrant()
    }
    private val syncEnabler = DeviceContactSyncEnabler(
        activity = this,
        permissionLauncher = contactPermissionLauncher,
        onEnabled = {
            invalidateOptionsMenu()
            if (accountSetup) finish()
        },
    )

    private val accountSetup: Boolean by lazy { intent.getBooleanExtra(EXTRA_ACCOUNT_SETUP, false) }

    /** The account-setup confirmation, while shown. */
    @androidx.annotation.VisibleForTesting
    internal var setupDialog: androidx.appcompat.app.AlertDialog? = null


    override fun onCreateUnlocked(savedInstanceState: Bundle?) {
        pendingScrollPosition = savedInstanceState?.getInt(STATE_SCROLL, 0) ?: 0
        try {
            pickMode = intent.getBooleanExtra(EXTRA_PICK_MODE, false)
            setContentView(R.layout.activity_contacts_list)
            applyThemeToActivity(this)
            applyTopInsetWithHeader(this, findViewById(R.id.contactsContent))
            applyKyPostTopBar(this, getString(if (pickMode) R.string.contacts_pick_title else R.string.contacts_title))

            recyclerView = findViewById(R.id.recyclerViewContacts)
            emptyText = findViewById(R.id.contactsEmptyText)
            bottomNav = findViewById(R.id.bottomNavigation)
            if (pickMode) {
                bottomNav.visibility = View.GONE
            } else {
                applyPrimaryNavigationInsets(this, bottomNav)
                setupPrimaryNavigation(this, bottomNav, R.id.nav_contacts)
                applyPrimaryNavigationTheme(this, bottomNav)
            }
            val addButton = findViewById<FloatingActionButton>(R.id.btnAddContact)

            adapter = ContactAdapter { contact ->
                if (pickMode) {
                    setResult(RESULT_OK, Intent().putExtra(EXTRA_RESULT_UID, contact.uid))
                    finish()
                } else {
                    startActivity(
                        Intent(this, ContactDetailActivity::class.java)
                            .putExtra(ContactDetailActivity.EXTRA_UID, contact.uid),
                    )
                }
            }
            recyclerView.layoutManager = LinearLayoutManager(this)
            recyclerView.adapter = adapter

            // No "create new contact" branch in pick mode — the user backs out and uses the
            // normal add-contact flow, then re-invokes the picker.
            if (pickMode) {
                addButton.visibility = View.GONE
            } else {
                addButton.setOnClickListener {
                    startActivity(Intent(this, ContactEditActivity::class.java))
                }
            }
        } catch (e: Exception) {
            android.util.Log.e("ContactsListActivity", "onCreate crashed", e)
            finish()
            return
        }

        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                try {
                    ContactsRuntime.graph(this@ContactsListActivity).repository.observeContacts().collect { contacts ->
                        render(contacts)
                    }
                } catch (e: Exception) {
                    if (e !is kotlinx.coroutines.CancellationException) {
                        android.util.Log.e("ContactsListActivity", "Error observing contacts", e)
                        Toast.makeText(this@ContactsListActivity, "Error loading contacts", Toast.LENGTH_SHORT).show()
                    }
                }
            }
        }

        // Opened for Settings' "Add account": turning device sync on is how the account is added.
        if (accountSetup && savedInstanceState == null) {
            if (DeviceContactsRuntime.graph(this).settings.isEnabled()) {
                PendingAccountSetup.complete(DeviceContactAccount.ACCOUNT_NAME)
                finish()
            } else {
                syncEnabler.checkAndEnable()
            }
        }
    }

    /** Leaving the add-account flow without turning sync on answers the waiting caller. Not on the
     *  lock redirect: the request is kept for after unlock (see MainActivity). */
    override fun onDestroy() {
        super.onDestroy()
        if (accountSetup && isFinishing && !redirectedToUnlock) PendingAccountSetup.cancel()
    }

    override fun onStartUnlocked() {
        // Observer only lives while the Contacts UI is visible — registering it globally caused
        // sync feedback loops. syncNowAsync() no-ops internally when device sync is disabled.
        val graph = DeviceContactsRuntime.graph(this)
        if (graph.settings.isEnabled()) {
            graph.observer.register()
            graph.coordinator.syncNowAsync()
        }

        if (!pickMode) {
            // On every resume, so a PGP identity set up on the web app shows without a re-sync.
            lifecycleScope.launch {
                adapter.selfHasPgpIdentity = hasPgpIdentity(this@ContactsListActivity)
            }
        }
    }

    override fun onStop() {
        super.onStop()
        if (redirectedToUnlock) return
        DeviceContactsRuntime.graph(this).observer.unregister()
    }

    override fun onResume() {
        super.onResume()
        if (redirectedToUnlock) return
        applyThemeToActivity(this)
        applyKyPostTopBar(this, getString(if (pickMode) R.string.contacts_pick_title else R.string.contacts_title))
        if (!pickMode) applyPrimaryNavigationTheme(this, bottomNav)
        applyEmptyStateBackground(this, emptyText)
        adapter.notifyDataSetChanged()
    }

    private fun render(contacts: List<ContactEntity>) {
        adapter.updateContacts(contacts)
        emptyText.visibility = if (contacts.isEmpty()) View.VISIBLE else View.GONE
        if (pendingScrollPosition > 0 && adapter.itemCount > 0) {
            val target = pendingScrollPosition.coerceAtMost(adapter.itemCount - 1)
            pendingScrollPosition = 0
            if (target >= 0) recyclerView.scrollToPosition(target)
        }
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        if (redirectedToUnlock) return
        // A position, not a contact. No names, addresses or numbers reach this Bundle.
        val layoutManager = recyclerView.layoutManager as? LinearLayoutManager
        val visible = layoutManager?.findFirstVisibleItemPosition() ?: 0
        outState.putInt(STATE_SCROLL, if (pendingScrollPosition > 0) pendingScrollPosition else visible)
    }

    @androidx.annotation.VisibleForTesting
    internal fun setPendingScrollForTest(position: Int) { pendingScrollPosition = position }

    @androidx.annotation.VisibleForTesting
    internal fun pendingScrollForTest(): Int = pendingScrollPosition

    override fun onCreateOptionsMenu(menu: Menu?): Boolean {
        if (redirectedToUnlock) return false
        // Pick mode is a lightweight contact-selection surface for other flows (e.g. PGP QR key
        // exchange) — no dedupe/refresh/device-sync affordances there, just pick-or-back-out.
        if (pickMode) return false
        menu?.add(0, MENU_REFRESH, 0, R.string.contacts_refresh)
        menu?.add(0, MENU_DEVICE_SYNC, 0, R.string.contacts_device_sync_enable)
        menu?.add(0, MENU_IMPORT_ACCOUNTS, 0, R.string.contacts_import_menu)
        menu?.add(0, MENU_DEDUPE, 0, R.string.contacts_dedupe)
        return super.onCreateOptionsMenu(menu)
    }

    override fun onPrepareOptionsMenu(menu: Menu?): Boolean {
        if (redirectedToUnlock) return false
        val deviceSyncItem = menu?.findItem(MENU_DEVICE_SYNC)
        if (deviceSyncItem != null) {
            try {
                val isEnabled = DeviceContactsRuntime.graph(this).settings.isEnabled()
                deviceSyncItem.title = getString(
                    if (isEnabled) R.string.contacts_device_sync_disable else R.string.contacts_device_sync_enable,
                )
                menu.findItem(MENU_IMPORT_ACCOUNTS)?.isVisible = isEnabled
            } catch (e: Exception) {
                android.util.Log.e("ContactsListActivity", "Error getting device sync status", e)
                deviceSyncItem.title = getString(R.string.contacts_device_sync_enable)
            }
        }
        return super.onPrepareOptionsMenu(menu)
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        return when (item.itemId) {
            MENU_REFRESH -> {
                // User-triggered, so — unlike the silent foreground/post-edit auto-sync — this one
                // reports its outcome back, matching the error table in Mobile_Contact_Sync.md.
                lifecycleScope.launch {
                    val message = when (val outcome = ContactsRuntime.graph(this@ContactsListActivity).repository.sync()) {
                        ContactSyncOutcome.Success -> getString(R.string.contacts_sync_success)
                        ContactSyncOutcome.NotPaired -> getString(R.string.connection_mode_relay_not_paired)
                        ContactSyncOutcome.Unauthorized -> getString(R.string.contacts_sync_unauthorized)
                        is ContactSyncOutcome.ServiceUnavailable -> outcome.message
                        is ContactSyncOutcome.Retry -> outcome.message
                    }
                    Toast.makeText(this@ContactsListActivity, message, Toast.LENGTH_SHORT).show()
                }
                true
            }
            MENU_DEVICE_SYNC -> {
                val graph = DeviceContactsRuntime.graph(this)
                if (graph.settings.isEnabled()) {
                    disableDeviceSync()
                } else {
                    syncEnabler.checkAndEnable()
                }
                true
            }
            MENU_IMPORT_ACCOUNTS -> {
                showImportAccounts()
                true
            }
            MENU_DEDUPE -> {
                lifecycleScope.launch {
                    val repository = ContactsRuntime.graph(this@ContactsListActivity).repository
                    val message = when (val outcome = repository.dedupe()) {
                        is ContactDedupeOutcome.Success -> {
                            repository.sync()
                            if (outcome.report.mergedCount == 0) {
                                getString(R.string.contacts_dedupe_none)
                            } else {
                                resources.getQuantityString(
                                    R.plurals.contacts_dedupe_result,
                                    outcome.report.mergedCount,
                                    outcome.report.mergedCount,
                                )
                            }
                        }
                        ContactDedupeOutcome.NotPaired -> getString(R.string.connection_mode_relay_not_paired)
                        ContactDedupeOutcome.Unauthorized -> getString(R.string.contacts_sync_unauthorized)
                        is ContactDedupeOutcome.ServiceUnavailable -> outcome.message
                        is ContactDedupeOutcome.Retry -> outcome.message
                    }
                    Toast.makeText(this@ContactsListActivity, message, Toast.LENGTH_SHORT).show()
                }
                true
            }
            else -> super.onOptionsItemSelected(item)
        }
    }

    /** Per-account consent: importing uploads those contacts to the server, so nothing is checked
     *  until the user checks it. */
    private fun showImportAccounts() {
        val graph = DeviceContactsRuntime.graph(this)
        lifecycleScope.launch {
            val accounts = graph.repository.foreignContactAccounts()
            if (accounts.isEmpty()) {
                Toast.makeText(this@ContactsListActivity, R.string.contacts_import_none, Toast.LENGTH_LONG).show()
                return@launch
            }
            // Consent belongs to this pairing; a different server or account starts with none.
            val destination = ContactsRuntime.graph(this@ContactsListActivity).repository.destination()
            if (destination == null) {
                Toast.makeText(this@ContactsListActivity, R.string.connection_mode_relay_not_paired, Toast.LENGTH_LONG).show()
                return@launch
            }
            val chosen = graph.settings.importAccounts(destination).toMutableSet()
            val padding = (16 * resources.displayMetrics.density).toInt()
            val container = android.widget.LinearLayout(this@ContactsListActivity).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                setPadding(padding, padding, padding, 0)
                addView(android.widget.TextView(context).apply { setText(R.string.contacts_import_message) })
                for (account in accounts) {
                    addView(
                        android.widget.CheckBox(context).apply {
                            text = account.name?.let { "$it (${account.type})" }
                                ?: getString(R.string.contacts_import_local_account)
                            isChecked = account.key in chosen
                            setOnCheckedChangeListener { _, checked ->
                                if (checked) chosen += account.key else chosen -= account.key
                            }
                        },
                    )
                }
            }
            androidx.appcompat.app.AlertDialog.Builder(this@ContactsListActivity)
                .setTitle(R.string.contacts_import_title)
                .setView(android.widget.ScrollView(this@ContactsListActivity).apply { addView(container) })
                .setPositiveButton(R.string.contacts_import_save) { _, _ ->
                    lifecycleScope.launch {
                        graph.settings.setImportAccounts(destination, chosen)
                        graph.coordinator.syncNowAsync()
                    }
                }
                .setNegativeButton(R.string.cancel, null)
                .create()
                .showSecurely()
        }
    }

    private fun disableDeviceSync() {
        val graph = DeviceContactsRuntime.graph(this)
        lifecycleScope.launch {
            try {
                graph.settings.setEnabled(false)
                DeviceContactSyncScheduler.cancelPeriodic(this@ContactsListActivity)
                graph.observer.unregister()
                graph.accountManager.removeAccount()
                Toast.makeText(
                    this@ContactsListActivity,
                    R.string.contacts_device_sync_disabled_toast,
                    Toast.LENGTH_SHORT,
                ).show()
                invalidateOptionsMenu()
            } catch (e: kotlinx.coroutines.CancellationException) {
                // The activity went away mid-disable. Rethrow rather than reporting it as a failure
                // and touching the UI of a destroyed activity — same rule as the collect above.
                throw e
            } catch (e: Exception) {
                Toast.makeText(
                    this@ContactsListActivity,
                    "Failed to disable device sync: ${e.message}",
                    Toast.LENGTH_SHORT,
                ).show()
            }
        }
    }

    companion object {
        private const val MENU_REFRESH = 0
        private const val MENU_DEVICE_SYNC = 1
        private const val MENU_DEDUPE = 2
        private const val MENU_IMPORT_ACCOUNTS = 3

        /** When true, a tap returns the uid via [EXTRA_RESULT_UID] instead of opening the editor. */
        const val EXTRA_PICK_MODE = "pick_mode"

        /** Opened by the contacts account's "Add account"; see [PendingAccountSetup]. */
        const val EXTRA_ACCOUNT_SETUP = "account_setup"
        const val EXTRA_RESULT_UID = "result_uid"

        private const val STATE_SCROLL = "contacts_scroll"
    }
}
