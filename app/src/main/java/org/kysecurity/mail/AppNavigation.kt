package org.kysecurity.mail

import android.app.Activity
import android.app.ActivityOptions
import android.content.Intent
import android.view.View
import android.widget.Toast
import com.google.android.material.navigation.NavigationBarView
import org.kysecurity.mail.contacts.ContactsListActivity
import org.kysecurity.mail.security.SecurityRuntime
import org.kysecurity.mail.security.SecuritySettingsActivity
import org.kysecurity.mail.security.UnlockActivity

fun applyPrimaryNavigationInsets(activity: Activity, nav: NavigationBarView) {
    if (activity.resources.getBoolean(R.bool.nav_is_rail)) {
        applyRailInsets(activity, nav)
    } else {
        applyBottomInset(nav)
    }
}

fun setupPrimaryNavigation(
    activity: Activity,
    nav: NavigationBarView,
    selectedItemId: Int,
    onInboxSelected: (() -> Unit)? = null,
) {
    fun navOrder(itemId: Int): Int = when (itemId) {
        R.id.nav_inbox -> 0
        R.id.nav_compose -> 1
        R.id.nav_contacts -> 3
        R.id.nav_settings -> 4
        else -> -1
    }

    fun startDestination(itemId: Int, intent: Intent) {
        val forward = navOrder(itemId) > navOrder(selectedItemId)
        val enter = if (forward) R.anim.nav_card_in_from_right else R.anim.nav_card_in_from_left
        val exit = if (forward) R.anim.nav_card_out_to_left else R.anim.nav_card_out_to_right
        val options = ActivityOptions.makeCustomAnimation(activity, enter, exit)
        activity.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_REORDER_TO_FRONT), options.toBundle())
    }

    fun lockOrOpenSecurity() {
        val graph = SecurityRuntime.graph(activity)
        if (!graph.appLockStore.isLockEnabled()) {
            Toast.makeText(activity, R.string.lock_disabled_open_security, Toast.LENGTH_SHORT).show()
            activity.startActivity(Intent(activity, SecuritySettingsActivity::class.java))
            return
        }
        graph.appLockManager.lockNow()
        activity.startActivity(Intent(activity, UnlockActivity::class.java))
    }

    nav.setOnItemSelectedListener { item ->
        when (item.itemId) {
            R.id.nav_inbox -> {
                if (selectedItemId == R.id.nav_inbox) {
                    onInboxSelected?.invoke()
                    true
                } else {
                    startDestination(R.id.nav_inbox, Intent(activity, InboxActivity::class.java))
                    false
                }
            }
            R.id.nav_compose -> {
                if (selectedItemId != R.id.nav_compose) {
                    // Same component as Reply/Forward, so REORDER_TO_FRONT finds an open one.
                    startDestination(R.id.nav_compose, ComposeActivity.internalIntent(activity))
                    false
                } else {
                    true
                }
            }
            R.id.nav_lock -> {
                lockOrOpenSecurity()
                false
            }
            R.id.nav_contacts -> {
                if (selectedItemId != R.id.nav_contacts) {
                    startDestination(R.id.nav_contacts, Intent(activity, ContactsListActivity::class.java))
                    false
                } else {
                    true
                }
            }
            R.id.nav_settings -> {
                if (selectedItemId != R.id.nav_settings) {
                    startDestination(R.id.nav_settings, Intent(activity, SettingsActivity::class.java))
                    false
                } else {
                    true
                }
            }
            else -> false
        }
    }
    nav.setOnItemReselectedListener { item ->
        if (item.itemId == R.id.nav_inbox && selectedItemId == R.id.nav_inbox) {
            onInboxSelected?.invoke()
        }
    }
    nav.menu.findItem(selectedItemId)?.isChecked = true
    nav.findViewById<View>(selectedItemId)?.isSelected = true
}
