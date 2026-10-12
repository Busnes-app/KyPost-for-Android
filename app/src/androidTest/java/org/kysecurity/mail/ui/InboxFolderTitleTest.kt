package org.kysecurity.mail.ui

import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.InboxActivity
import org.kysecurity.mail.KeywordTabs

/** A folder opened from the folders screen is titled by its own name, not "Inbox". */
@RunWith(AndroidJUnit4::class)
class InboxFolderTitleTest {

    @Test
    fun aCustomFolderIsTitledByItsLeaf() {
        ActivityScenario.launch(InboxActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                activity.setFolderForTest("INBOX.Work.Receipts", KeywordTabs.ALL)
                assertEquals("KyPost - Receipts", activity.title.toString())
                activity.setFolderForTest("INBOX", KeywordTabs.ALL)
                assertEquals("KyPost - Inbox", activity.title.toString())
            }
        }
    }
}
