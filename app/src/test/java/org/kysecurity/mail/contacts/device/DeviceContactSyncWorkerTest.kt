package org.kysecurity.mail.contacts.device

import kotlinx.coroutines.runBlocking
import org.kysecurity.mail.contacts.ContactSyncOutcome
import kotlin.test.Test
import kotlin.test.assertEquals

/** The periodic worker is the only background path to the server; it must not be device-only. */
class DeviceContactSyncWorkerTest {

    @Test
    fun serverSyncRunsBeforeTheDevicePass() = runBlocking {
        val calls = mutableListOf<String>()

        val failed = runContactSync(
            server = { calls += "server"; ContactSyncOutcome.Success },
            device = { calls += "device"; emptyList() },
        )

        assertEquals(listOf("server", "device"), calls)
        assertEquals(emptyList(), failed)
    }

    @Test
    fun aServerFailureIsReported_andTheDevicePassStillRuns() = runBlocking {
        var deviceRan = false

        val failed = runContactSync(
            server = { ContactSyncOutcome.Retry("offline") },
            device = { deviceRan = true; listOf("refreshGroups") },
        )

        assertEquals(listOf("serverSync", "refreshGroups"), failed)
        assertEquals(true, deviceRan)
    }
}
