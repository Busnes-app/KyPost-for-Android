package org.kysecurity.mail.security

import android.annotation.SuppressLint
import android.net.http.X509TrustManagerExtensions
import java.net.Socket
import java.security.KeyStore
import java.security.PublicKey
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLEngine
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509ExtendedTrustManager

/** The TLS key floor for every connection this app opens: RSA >= 2048 or EC >= 256 bits on every
 *  certificate of the platform-validated chain, anchor included. Per client, never process-wide. */
internal object StrongTls {
    fun platformTrustManager(): X509ExtendedTrustManager =
        TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()).apply {
            init(null as KeyStore?)
        }.trustManagers.filterIsInstance<X509ExtendedTrustManager>().single()

    fun context(trust: StrongTrustManager): SSLContext =
        SSLContext.getInstance("TLS").apply { init(null, arrayOf(trust), null) }

    fun meetsFloor(key: PublicKey): Boolean = when (key) {
        is RSAPublicKey -> key.modulus.bitLength() >= 2048
        is ECPublicKey -> (key.params?.curve?.field?.fieldSize ?: 0) >= 256
        else -> false
    }

    /** Throws unless [trusted] is non-empty and every key meets [meetsFloor]. */
    fun requireStrongChain(trusted: List<X509Certificate>) {
        if (trusted.isEmpty() || trusted.any { !meetsFloor(it.publicKey) }) {
            throw CertificateException("TLS certificate key is below KyPost's strength requirement")
        }
    }

    /** Platform trust, hostname and network-security-config checks run first, then the floor.
     *  Public [checkServerTrusted] with a host is what `X509TrustManagerExtensions` (and so
     *  OkHttp's Android chain cleaner) reflects on; keep its signature. */
    @SuppressLint("CustomX509TrustManager") // Delegates every decision to the platform, then narrows.
    class StrongTrustManager(private val platform: X509ExtendedTrustManager) : X509ExtendedTrustManager() {
        // Lazy: constructing it needs the Android runtime, and JVM tests build this class.
        private val extensions by lazy { X509TrustManagerExtensions(platform) }

        fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, host: String?): List<X509Certificate> {
            if (host.isNullOrEmpty()) throw CertificateException("TLS peer hostname is unavailable")
            // The platform-built path includes its selected anchor; the wire chain may omit it.
            return extensions.checkServerTrusted(chain, authType, host).also(::requireStrongChain)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) {
            platform.checkServerTrusted(chain, authType, socket)
            checkServerTrusted(chain, authType, (socket as? SSLSocket)?.handshakeSession?.peerHost)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) {
            platform.checkServerTrusted(chain, authType, engine)
            checkServerTrusted(chain, authType, engine.handshakeSession?.peerHost)
        }

        override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
            throw CertificateException("Hostname-aware TLS verification is required")
        }

        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) =
            platform.checkClientTrusted(chain, authType)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, socket: Socket) =
            platform.checkClientTrusted(chain, authType, socket)
        override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String, engine: SSLEngine) =
            platform.checkClientTrusted(chain, authType, engine)
        override fun getAcceptedIssuers(): Array<X509Certificate> = platform.acceptedIssuers
    }
}
