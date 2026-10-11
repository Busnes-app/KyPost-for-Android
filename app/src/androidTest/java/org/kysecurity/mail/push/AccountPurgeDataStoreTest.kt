package org.kysecurity.mail.push

import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.contacts.contactsDataStore
import org.kysecurity.mail.mail.mailSyncDataStore

/** Unpair deletes these stores' files while their DataStores are live; the cached values must go
 *  too, or the next pairing in this process resumes from the old account's cursors. */
@RunWith(AndroidJUnit4::class)
class AccountPurgeDataStoreTest {

    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val probe = stringPreferencesKey("probe")

    @Test
    fun unpair_dropsCachedMailSyncState(): Unit = runBlocking {
        context.mailSyncDataStore.edit { it[probe] = "stale" }

        PushRuntime.graph(context).repository.clearPairing()

        assertEquals(emptyMap<Any, Any>(), context.mailSyncDataStore.data.first().asMap())
    }

    @Test
    fun unpair_dropsCachedContactsState(): Unit = runBlocking {
        context.contactsDataStore.edit { it[probe] = "stale" }

        PushRuntime.graph(context).repository.clearPairing()

        assertEquals(emptyMap<Any, Any>(), context.contactsDataStore.data.first().asMap())
    }
}
