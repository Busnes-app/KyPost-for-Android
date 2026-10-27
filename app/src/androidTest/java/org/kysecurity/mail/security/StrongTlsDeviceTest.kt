package org.kysecurity.mail.security

import androidx.test.ext.junit.runners.AndroidJUnit4
import okhttp3.OkHttpClient
import okhttp3.Request
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.kysecurity.mail.PinPosture
import org.kysecurity.mail.pairingHttpClient
import java.net.InetAddress
import java.security.KeyFactory
import java.security.KeyStore
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec
import java.util.concurrent.atomic.AtomicInteger
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLServerSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager
import kotlin.concurrent.thread

/** Real Android TLS on loopback, fixtures from `scripts/tls-fixtures.sh`. Each weak case is first
 *  shown to pass the platform alone, so its refusal is the key floor's and nothing else's. */
@RunWith(AndroidJUnit4::class)
class StrongTlsDeviceTest {
    private class Peer(val leaf: String, val wire: List<String>, val anchor: String = "root_rsa2048")

    private val strong = listOf(
        Peer("leaf_rsa2048", listOf("leaf_rsa2048")),
        Peer("leaf_p256", listOf("leaf_p256")),
    )
    private val weak = listOf(
        Peer("leaf_rsa1024", listOf("leaf_rsa1024")),
        Peer("leaf_under_weak_intermediate", listOf("leaf_under_weak_intermediate", "intermediate_rsa2047")),
        // The weak anchor is never on the wire; only the platform-built path reveals it.
        Peer("leaf_under_weak_root", listOf("leaf_under_weak_root"), anchor = "root_rsa2047"),
    )

    @Test fun strongChainsConnect() {
        for (peer in strong) serve(peer) { url, served ->
            assertEquals(peer.leaf, 200, call(guarded(peer), url))
            assertEquals(peer.leaf, 1, served.get())
        }
    }

    /** The platform may already refuse SHA-1; either way the guarded client must. */
    @Test fun sha1SignedLeavesAreRefused() {
        val peer = Peer("leaf_sha1", listOf("leaf_sha1"))
        serve(peer) { url, _ ->
            val platform = runCatching { call(platformOnly(peer), url) }
            android.util.Log.i("StrongTlsDeviceTest", "platform alone on SHA-1 leaf: $platform")
        }
        serve(peer) { url, served ->
            assertTrue(runCatching { call(guarded(peer), url) }.isFailure)
            assertEquals(0, served.get())
        }
    }

    @Test fun weakKeysAnywhereInTheChainAreRefusedBeforeAnyRequest() {
        for (peer in weak) {
            serve(peer) { url, served ->
                assertEquals("platform control ${peer.leaf}", 200, call(platformOnly(peer), url))
                assertEquals(1, served.get())
            }
            serve(peer) { url, served ->
                assertTrue(peer.leaf, runCatching { call(guarded(peer), url) }.isFailure)
                assertEquals("${peer.leaf} received a request", 0, served.get())
            }
        }
    }

    /** OkHttp's pin check runs on the path our manager returns, so the leaf pin must still work. */
    @Test fun leafPinsStillDecideOnTheGuardedPath() {
        val peer = strong.first()
        val pin = SpkiPinner.pinFor(cert(peer.leaf))
        serve(peer) { url, _ -> assertEquals(200, call(guarded(peer, PinPosture.Pinned("127.0.0.1", setOf(pin))), url)) }
        val wrong = "sha256/" + "A".repeat(43) + "="
        serve(peer) { url, served ->
            assertTrue(runCatching { call(guarded(peer, PinPosture.Pinned("127.0.0.1", setOf(wrong))), url) }.isFailure)
            assertEquals(0, served.get())
        }
    }

    @Test fun platformHostnameChecksStillApply() {
        val peer = strong.first()
        serve(peer) { url, served ->
            assertTrue(runCatching { call(guarded(peer), url.replace("127.0.0.1", "localhost")) }.isFailure)
            assertEquals(0, served.get())
        }
    }

    private fun resource(name: String): ByteArray =
        requireNotNull(javaClass.classLoader!!.getResourceAsStream("tls/$name")) { name }.use { it.readBytes() }

    private fun cert(name: String): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(resource("$name.crt").inputStream()) as X509Certificate

    private fun fixtureTrust(anchor: String): X509ExtendedTrustManager {
        val roots = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setCertificateEntry("fixture", cert(anchor))
        }
        return TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply { init(roots) }
            .trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()
    }

    /** The production client with only its trust anchors scoped to the fixture. */
    private fun guarded(peer: Peer, posture: PinPosture = PinPosture.TofuWindow): OkHttpClient {
        val trust = StrongTls.StrongTrustManager(fixtureTrust(peer.anchor))
        return pairingHttpClient(posture, 10_000).newBuilder()
            .sslSocketFactory(StrongTls.context(trust).socketFactory, trust).build()
    }

    private fun platformOnly(peer: Peer): OkHttpClient {
        val trust = fixtureTrust(peer.anchor)
        val context = SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }
        return pairingHttpClient(PinPosture.TofuWindow, 10_000).newBuilder()
            .sslSocketFactory(context.socketFactory, trust).build()
    }

    private fun call(client: OkHttpClient, url: String): Int = try {
        client.newCall(Request.Builder().url(url).build()).execute().use { it.code }
    } finally {
        client.connectionPool.evictAll()
    }

    /** One loopback TLS server per block; counts requests that got past the handshake. */
    private fun serve(peer: Peer, block: (String, AtomicInteger) -> Unit) {
        val algorithm = if (peer.leaf.contains("p256")) "EC" else "RSA"
        val key = KeyFactory.getInstance(algorithm).generatePrivate(PKCS8EncodedKeySpec(resource("${peer.leaf}.key.der")))
        val store = KeyStore.getInstance(KeyStore.getDefaultType()).apply {
            load(null)
            setKeyEntry("leaf", key, "fixture".toCharArray(), peer.wire.map(::cert).toTypedArray())
        }
        val keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(store, "fixture".toCharArray()) }
        val context = SSLContext.getInstance("TLS").apply { init(keys.keyManagers, null, null) }
        val server = context.serverSocketFactory.createServerSocket(0, 8, InetAddress.getByName("127.0.0.1")) as SSLServerSocket
        val served = AtomicInteger()
        val worker = thread(isDaemon = true) {
            while (!server.isClosed) {
                val socket = runCatching { server.accept() }.getOrNull() ?: break
                runCatching {
                    socket.use {
                        socket.soTimeout = 10_000
                        val reader = socket.getInputStream().bufferedReader()
                        if (reader.readLine().isNullOrEmpty()) return@use
                        while (!reader.readLine().isNullOrEmpty()) Unit
                        served.incrementAndGet()
                        socket.getOutputStream().write("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".toByteArray())
                    }
                }
            }
        }
        try {
            block("https://127.0.0.1:${server.localPort}/probe", served)
        } finally {
            server.close()
            worker.join(5_000)
        }
    }
}
