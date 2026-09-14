package org.kysecurity.mail

import org.kysecurity.mail.pgp.PgpBootstrapClient
import org.kysecurity.mail.pgp.PgpComposeState
import org.kysecurity.mail.pgp.RecipientKeyClient
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.testing.FakeCallFactory
import org.kysecurity.mail.testing.response
import kotlinx.coroutines.runBlocking
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.Before
import org.junit.Test

private fun testPairing(deviceId: String = "d", deviceSecret: String = "s") = PairingData(
    subscriberId = "sub-1",
    serverUrl = "https://relay.example.com",
    registrationUrl = "",
    pairingToken = "",
    deviceId = deviceId,
    deviceSecret = deviceSecret,
    pairedAtEpochMs = 0L,
)

class ComposePgpControllerTest {

    /** The bootstrap cache is process-scoped, so it has to be cleared between tests. */
    @Before
    fun clearCache() = ComposePgpController.resetSessionCache()

    @Test
    fun draftHandoffFailsClosedExceptForKnownClientCustody() {
        val refused = org.kysecurity.mail.pgp.DraftHandoffMode.REFUSE
        for (protection in listOf(null, "server", "future")) {
            assertEquals(refused, org.kysecurity.mail.pgp.draftHandoffMode(true, protection, true, "me@example.com"))
        }
        assertEquals(refused, org.kysecurity.mail.pgp.draftHandoffMode(false, "client", true, "me@example.com"))
        assertEquals(refused, org.kysecurity.mail.pgp.draftHandoffMode(true, "client", true, ""))
        assertEquals(org.kysecurity.mail.pgp.DraftHandoffMode.OPEN_WITHOUT_SAVE,
            org.kysecurity.mail.pgp.draftHandoffMode(true, "client", false, ""))
        assertEquals(org.kysecurity.mail.pgp.DraftHandoffMode.ENCRYPT_AND_SAVE,
            org.kysecurity.mail.pgp.draftHandoffMode(true, "client", true, "me@example.com"))
    }

    @Test
    fun splitAddresses_flattensTheThreeCommaJoinedFields() {
        assertEquals(
            listOf("a@example.com", "b@example.com", "c@example.com"),
            splitAddresses("a@example.com, b@example.com", "", "c@example.com"),
        )
    }

    @Test
    fun splitAddresses_deduplicatesCaseInsensitively() {
        assertEquals(
            listOf("a@example.com"),
            splitAddresses("a@example.com", "A@Example.com", ""),
        )
    }

    @Test
    fun splitAddresses_dropsBlanksAndTrimsWhitespace() {
        assertEquals(listOf("a@example.com"), splitAddresses(" a@example.com , , ", "", ""))
    }

    @Test
    fun composeState_mapsBootstrapThroughPgpComposeStateOf() = runBlocking {
        val controller = controllerWith(bootstrapBody = """{"hasIdentity":true,"protection":"server"}""")

        assertEquals(
            PgpComposeState(canEncrypt = true, canSign = true, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    @Test
    fun composeState_withoutPairing_hidesEverything() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertEquals(
            PgpComposeState(canEncrypt = false, canSign = false, handoffToWebmail = false),
            controller.composeState(),
        )
    }

    @Test
    fun composeState_cachesASuccessForTheProcess() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, """{"hasIdentity":true,"protection":"server"}""", 200)
        }
        val firstController = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )
        val secondController = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        firstController.composeState()
        secondController.composeState()

        assertEquals(1, calls)
    }

    @Test
    fun composeState_doesNotCacheAFailure() = runBlocking {
        var calls = 0
        val callFactory = FakeCallFactory { request ->
            calls++
            response(request, "unavailable", 503)
        }
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
        )

        controller.composeState()
        controller.composeState()

        assertEquals(2, calls)
    }

    @Test
    fun composeState_cachesBootstrapButReprobesEnrollment() = runBlocking {
        var calls = 0
        var enrolled = false
        val callFactory = FakeCallFactory { request ->
            calls++
            response(
                request,
                """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["me@example.com"]}""",
                200,
            )
        }
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(callFactory = callFactory),
            recipientKeyClient = RecipientKeyClient(callFactory = callFactory),
            enrollmentProbe = { enrolled },
        )

        assertTrue(controller.composeState().handoffToWebmail, "unenrolled device hands off")
        assertEquals(org.kysecurity.mail.pgp.DraftHandoffMode.OPEN_WITHOUT_SAVE, controller.draftHandoffMode())

        enrolled = true

        assertTrue(controller.composeState().clientSide, "enrolling mid-session must take effect")
        assertEquals(org.kysecurity.mail.pgp.DraftHandoffMode.ENCRYPT_AND_SAVE, controller.draftHandoffMode())
        enrolled = false
        assertEquals(org.kysecurity.mail.pgp.DraftHandoffMode.OPEN_WITHOUT_SAVE, controller.draftHandoffMode())
        assertEquals(1, calls, "bootstrap itself is still cached")
    }

    @Test
    fun accountAddress_comesFromSuggestedUserIds() = runBlocking {
        val controller = controllerWith(
            bootstrapBody = """{"hasIdentity":true,"protection":"client","suggestedUserIDs":["me@example.com","alias@example.com"]}""",
        )

        assertEquals("me@example.com", controller.accountAddress())
    }

    @Test
    fun accountAddress_isBlankWhenBootstrapFails() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { testPairing() },
            bootstrapClient = PgpBootstrapClient(
                callFactory = FakeCallFactory { request -> response(request, "boom", 503) },
            ),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertEquals("", controller.accountAddress())
    }

    @Test
    fun keylessRecipients_returnsTheAddressesWithNoKeyOnFile() = runBlocking {
        val body = """{"results":[
            {"address":"a@example.com","hasKey":true,"revoked":false,"expired":false,"tier":"contact-verified"},
            {"address":"b@example.com","hasKey":false,"revoked":false,"expired":false,"tier":"none"}
        ]}"""
        val controller = controllerWith(recipientBody = body)

        assertEquals(
            listOf("b@example.com"),
            controller.keylessRecipients(listOf("a@example.com", "b@example.com")),
        )
    }

    /** The server's 409 is the real gate, so a failed lookup must never force the fallback. */
    @Test
    fun keylessRecipients_isEmptyOnFailure() = runBlocking {
        val controller = controllerWith(recipientStatus = 500, recipientBody = "boom")

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    @Test
    fun keylessRecipients_withoutPairing_isEmpty() = runBlocking {
        val controller = ComposePgpController(
            pairingProvider = { null },
            bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
            recipientKeyClient = RecipientKeyClient(callFactory = FakeCallFactory { request -> response(request, "{}", 200) }),
        )

        assertTrue(controller.keylessRecipients(listOf("a@example.com")).isEmpty())
    }

    private fun controllerWith(
        bootstrapBody: String = """{"hasIdentity":true,"protection":"server"}""",
        recipientBody: String = """{"results":[]}""",
        recipientStatus: Int = 200,
    ) = ComposePgpController(
        pairingProvider = { testPairing() },
        bootstrapClient = PgpBootstrapClient(callFactory = FakeCallFactory { request -> response(request, bootstrapBody, 200) }),
        recipientKeyClient = RecipientKeyClient(
            callFactory = FakeCallFactory { request -> response(request, recipientBody, recipientStatus) },
        ),
    )
}
