package org.kysecurity.mail.contacts.device

import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.kysecurity.mail.contacts.ContactCursorStore
import org.kysecurity.mail.contacts.ContactSyncClient
import org.kysecurity.mail.contacts.ContactSyncRepository
import org.kysecurity.mail.contacts.GroupSyncRepository
import org.kysecurity.mail.contacts.GroupsSyncClient
import org.kysecurity.mail.data.AppDatabase
import kotlinx.coroutines.runBlocking
import okhttp3.OkHttpClient
import org.junit.After
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/** A group refresh that did not happen is a failed stage, so the worker retries instead of
 *  reporting success over stale groups. */
@RunWith(AndroidJUnit4::class)
class DeviceContactSyncStagesTest {
    private val context = ApplicationProvider.getApplicationContext<android.content.Context>()
    private val db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).build()

    @After
    fun tearDown() = db.close()

    @Test
    fun aGroupRefreshThatDidNotHappen_isReportedAsAFailedStage() = runBlocking {
        val repository = DeviceContactRepository(
            context = context,
            db = db,
            syncRepository = ContactSyncRepository(
                db = db,
                client = ContactSyncClient(callFactory = OkHttpClient()),
                cursorStore = ContactCursorStore(context, db),
                pairingProvider = { null },
            ),
            groupSyncRepository = GroupSyncRepository(db, GroupsSyncClient(callFactory = OkHttpClient())) { null },
        )

        val failed = repository.syncAll()

        assertTrue("got $failed", "refreshGroups" in failed)
    }
}
