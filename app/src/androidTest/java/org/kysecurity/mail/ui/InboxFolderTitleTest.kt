package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import com.google.android.material.navigation.NavigationBarView
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs
import org.kysecurity.mail.R

/** A folder opened from the folders screen is labelled by its own name, not "Inbox". The window
 *  title is always the app name (`applyKyPostTopBar`); the label is the Inbox tab's. */
@RunWith(AndroidJUnit4::class)
class InboxFolderTitleTest {

    @Test
    fun aCustomFolderIsTitledByItsLeaf() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                val tab = activity.findViewById<NavigationBarView>(R.id.bottomNavigation).menu.findItem(R.id.nav_inbox)
                activity.setFolderForTest("INBOX.Work.Receipts", KeywordTabs.ALL)
                assertEquals("Receipts", tab.title.toString())
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                assertEquals(activity.getString(R.string.nav_inbox), tab.title.toString())
            }
        }
    }
}
