package org.kysecurity.mail.contacts.device

import android.accounts.AccountManager
import android.content.ContentResolver
import android.content.Intent
import android.provider.ContactsContract
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** The platform must see KyPost as the contacts sync adapter for its own account type, and the
 *  authenticator must answer Settings' calls instead of returning nothing or throwing. */
@RunWith(AndroidJUnit4::class)
class ContactSyncAdapterDeclarationTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()

    @Test
    fun theSyncAdapterIsRegisteredForOurContactsAccount() {
        val adapter = ContentResolver.getSyncAdapterTypes().singleOrNull {
            it.accountType == DeviceContactAccount.ACCOUNT_TYPE && it.authority == ContactsContract.AUTHORITY
        }

        assertNotNull("no contacts sync adapter registered for ${DeviceContactAccount.ACCOUNT_TYPE}", adapter)
        assertTrue("contacts apps need an uploading adapter to allow edits", adapter!!.supportsUploading())
        assertFalse(adapter.isUserVisible)
    }

    @Test
    fun addAccount_opensTheContactsScreen() {
        val result = KyPostContactAuthenticator(context)
            .addAccount(null, DeviceContactAccount.ACCOUNT_TYPE, null, null, null)

        @Suppress("DEPRECATION")
        val intent = result.getParcelable<Intent>(AccountManager.KEY_INTENT)
        assertEquals(
            "org.kysecurity.mail.contacts.ContactsListActivity",
            intent?.component?.className,
        )
        assertEquals(context.packageName, intent?.component?.packageName)
    }

    @Test
    fun editProperties_answersInsteadOfThrowing() {
        assertNull(KyPostContactAuthenticator(context).editProperties(null, DeviceContactAccount.ACCOUNT_TYPE))
    }
}
