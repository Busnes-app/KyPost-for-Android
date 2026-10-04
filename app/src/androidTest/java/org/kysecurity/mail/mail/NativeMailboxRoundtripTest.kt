package org.kysecurity.mail.mail

import androidx.room.Room
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.net.URI
import java.security.KeyStore
import java.security.cert.CertificateFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager
import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assume.assumeTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.data.AppDatabase
import org.kysecurity.mail.pairingHttpClient
import org.kysecurity.mail.push.NativeRegistrationClient
import org.kysecurity.mail.push.NativeRegistrationResult
import org.kysecurity.mail.push.PairingData
import org.kysecurity.mail.push.SecurePairingStore

/** Run only against the server's disposable native/TLS SMTP fixture via adb reverse.
 * Real registration, leaf pin, Keystore preferences, Room and client mail transports.
 * The test CA is scoped to this client; certificate-chain and hostname checks stay enforced.
 */
@RunWith(AndroidJUnit4::class)
class NativeMailboxRoundtripTest {
    @Test
    fun nativeAccountRoundtripsWithoutImap() = runBlocking {
        val args = InstrumentationRegistry.getArguments()
        val server = args.getString("nativeServer")
        assumeTrue("Requires the opt-in disposable server fixture", server != null)
        val origin = URI(requireNotNull(server))
        require(origin.scheme == "https" && origin.host == "127.0.0.1" && origin.port in 1..65535 &&
            origin.userInfo == null && origin.rawPath.isNullOrEmpty() && origin.rawQuery == null && origin.rawFragment == null)
        val pin = requireNotNull(args.getString("nativePin"))
        val caPath = requireNotNull(args.getString("nativeCA"))
        require(caPath.startsWith("/data/local/tmp/kypost-native-") && caPath.endsWith(".pem"))
        val ca = File(caPath).inputStream().use { CertificateFactory.getInstance("X.509").generateCertificate(it) }
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("disposable-native-fixture", ca)
        }
        val trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(roots) }
        val manager = trust.trustManagers.single() as X509TrustManager
        val tls = SSLContext.getInstance("TLS").apply { init(null, arrayOf(manager), null) }
        val client = pairingHttpClient(PinPosture.Pinned("127.0.0.1", setOf(pin)), 15_000)
            .newBuilder().sslSocketFactory(tls.socketFactory, manager).build()
        val context = InstrumentationRegistry.getInstrumentation().targetContext
        val store = SecurePairingStore(context)
        val db = Room.inMemoryDatabaseBuilder(context, AppDatabase::class.java).allowMainThreadQueries().build()
        try {
            store.clearPairing()
            val incoming = PairingData(
                subscriberId = requireNotNull(args.getString("nativeSubscriber")),
                serverUrl = server,
                registrationUrl = "$server/api/notifications/native/register",
                pairingToken = requireNotNull(args.getString("nativePairingToken")),
                deviceId = null,
                deviceSecret = null,
                pairedAtEpochMs = System.currentTimeMillis(),
                spkiPin = pin,
            )
            val registration = NativeRegistrationClient(callFactory = client).register(incoming, "synthetic-android-native-token")
            assertTrue("Real device registration must succeed: $registration", registration is NativeRegistrationResult.Success)
            registration as NativeRegistrationResult.Success
            assertFalse(registration.deviceId.isNullOrBlank())
            assertFalse(registration.deviceSecret.isNullOrBlank())
            assertEquals(setOf(pin), registration.tlsPin?.spkiSha256)
            store.savePairing(incoming.copy(deviceId = registration.deviceId, deviceSecret = registration.deviceSecret, spkiPin = null), gateEnabled = false)
            store.saveTlsPin(requireNotNull(registration.tlsPin))
            val reloaded = SecurePairingStore(context)
            val pairing = requireNotNull(reloaded.pairing.value)
            assertEquals(registration.deviceSecret, pairing.deviceSecret)
            assertEquals(setOf(pin), reloaded.currentTlsPin()?.spkiSha256)
            val cursors = MailCursorStore(context)
            val relay = RelayMailSource({ pairing }, cursors, callFactory = client)
            val repository = MailRepository(db.emailDao(), relay, cursors)
            fun <T> success(result: MailOutcome<T>): T {
                assertTrue("Native mail call must succeed: $result", result is MailOutcome.Success)
                return (result as MailOutcome.Success).value
            }
            val snapshot = success(repository.refreshFolder("INBOX", forceFullResync = true))
            assertFalse(snapshot.isDelta)
            val email = repository.cachedEmails("INBOX").single()
            assertTrue("Native reference must survive real Room", email.id.matches(Regex("n1:[^:]+:[0-9]+")))
            assertEquals("incoming native roundtrip", email.subject)
            assertTrue(email.keywords.contains("Travel"))
            assertEquals("incoming body <visible@outside.test>", success(repository.fetchBody(email.id, "INBOX")).html)
            assertEquals("plain", db.emailDao().getById(email.id, "INBOX")?.bodyMode)
            success(repository.refreshFolder("INBOX", forceFullResync = true))
            assertEquals("incoming body <visible@outside.test>", db.emailDao().getById(email.id, "INBOX")?.body)
            val attachment = success(repository.listAttachments(email.id, "INBOX")).single()
            assertEquals("file.bin", attachment.name)
            assertArrayEquals("native attachment\u0000exact bytes".toByteArray(), success(repository.downloadAttachment(email.id, "INBOX", attachment.index)).bytes)
            success(repository.markRead(email.id, "INBOX"))
            success(repository.refreshFolder("INBOX", forceFullResync = true))
            assertEquals("read", repository.cachedEmails("INBOX").single().status)
            val wrong = RelayMailSource({ pairing.copy(deviceSecret = "wrong-device-secret") }, cursors, callFactory = client)
            assertTrue(wrong.fetchInbox("INBOX", 50) is MailOutcome.Unauthorized)
            val generation = email.id.split(":")[1]
            val foreign = (if (generation.startsWith("0")) "1" else "0") + generation.drop(1)
            val stale = "n1:$foreign:" + email.id.substringAfterLast(":")
            assertTrue(relay.fetchMessageBody(stale, "INBOX") is MailOutcome.BadRequest)
            val badPin = "sha256/" + java.util.Base64.getEncoder().encodeToString(ByteArray(32))
            val mismatched = pairingHttpClient(PinPosture.Pinned("127.0.0.1", setOf(badPin)), 15_000)
                .newBuilder().sslSocketFactory(tls.socketFactory, manager).build()
            try {
                val untrusted = RelayMailSource({ pairing }, cursors, callFactory = mismatched)
                assertTrue(untrusted.fetchInbox("INBOX", 50) is MailOutcome.CertificateMismatch)
            } finally {
                mismatched.connectionPool.evictAll()
                mismatched.dispatcher.executorService.shutdown()
            }
            val send = success(repository.send(MailDraft(to = "visible@outside.test", bcc = "hidden@outside.test", subject = "ordinary", body = "native compose")))
            assertTrue("SMTP acceptance must include retained Sent", send.sentSaved)
            success(repository.refreshFolder("Sent", forceFullResync = true))
            assertEquals("ordinary", repository.cachedEmails("Sent").single().subject)
        } finally {
            db.close()
            store.clearPairing()
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }
}
