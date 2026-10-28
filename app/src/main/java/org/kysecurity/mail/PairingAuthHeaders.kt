package org.kysecurity.mail

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody
import okio.Buffer
import okio.BufferedSource
import okio.ForwardingSource
import okio.buffer
import org.kysecurity.mail.security.StrongTls
import java.io.IOException

/** Credentialed clients take an injected `Call.Factory` with no default, so none skips pinning. */
const val HEADER_DEVICE_ID = "X-Kypost-Device-Id"
const val HEADER_DEVICE_SECRET = "X-Kypost-Device-Secret"

/** Each registration mints a new deviceSecret that invalidates the previous one; persist it. */
fun Request.Builder.pairingAuthHeaders(deviceId: String, deviceSecret: String): Request.Builder =
    header(HEADER_DEVICE_ID, deviceId).header(HEADER_DEVICE_SECRET, deviceSecret)

/** No default posture: `grep TofuWindow` is the complete audit of the unpinned surface. */
sealed interface PinPosture {
    /** [spkiSha256] is ONE leaf pin for anything captured under the current rule; only installs
     *  pinned before it still carry a whole-chain set, and they narrow on the next successful
     *  resync. Never widen this to an issuer — see [org.kysecurity.mail.security.SpkiPinner.pinsForChain]. */
    data class Pinned(val host: String, val spkiSha256: Set<String>) : PinPosture

    /** Only legitimate before any pairing completes; a pin that existed and is gone fails closed. */
    object TofuWindow : PinPosture
}

/** A leaf-SPKI pin carried in the pairing QR/deep link, attached to the registration request with
 *  `.tag(LinkPin::class.java, ...)` so the very first call is pinned.
 *
 *  Scope, precisely: this closes the hostile-NETWORK hole, where a locally trusted CA intercepts
 *  the one request that carries `pairingToken` and the WebPush keys. It does NOT defend a hostile
 *  LINK -- whoever writes the link can omit `pin` and put us back in the TOFU window. The link
 *  itself is trusted out-of-band, by the user reading it off their own relay. */
data class LinkPin(val host: String, val spkiSha256: String)

/** Normalises a `pin` link parameter to OkHttp's `sha256/<base64>` form, or null if it is not a
 *  base64 SHA-256. Null must fail the pairing: a pin we cannot parse is not a reason to downgrade. */
fun normalizeSpkiPin(raw: String): String? {
    val body = raw.trim().removePrefix("sha256/")
    // 32 raw bytes of SHA-256 is exactly 44 base64 characters with one '=' of padding.
    if (!Regex("^[A-Za-z0-9+/]{43}=$").matches(body)) return null
    return "sha256/" + body
}

/** Redirects disabled: OkHttp does not strip our custom credential headers cross-host.
 *  Every app-owned connection is built here, so this is where the TLS policy lives: TLS 1.2+
 *  with forward-secret AEAD suites only, and [StrongTls]'s key floor on the validated chain. */
private val basePairingClient: OkHttpClient by lazy {
    val trust = StrongTls.StrongTrustManager(StrongTls.platformTrustManager())
    OkHttpClient.Builder()
        .sslSocketFactory(StrongTls.context(trust).socketFactory, trust)
        .connectionSpecs(listOf(ConnectionSpec.RESTRICTED_TLS))
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor(BodySizeLimitInterceptor())
        .build()
}

/** [callTimeoutMillis] bounds the whole call: cancellation cannot interrupt a socket read. */
fun pairingHttpClient(posture: PinPosture, callTimeoutMillis: Long? = null): OkHttpClient {
    val builder = basePairingClient.newBuilder()
    when (posture) {
        // Whatever the set holds is registered for this host, and `CertificatePinner` passes on the
        // FIRST chain member matching ANY of them. That is why the set may only ever hold leaves:
        // one issuer pin in here would admit every certificate that issuer signs. Renewal with a
        // new key is a re-trust through `reconnectToServer`, not a pin to relax.
        is PinPosture.Pinned -> {
            // Empty would configure no pin for the host, which CertificatePinner passes vacuously.
            // TlsPin makes that unrepresentable; this is the second half of the same guarantee.
            require(posture.spkiSha256.isNotEmpty()) { "Refusing to build a client that pins nothing" }
            builder.certificatePinner(
                CertificatePinner.Builder()
                    .apply { posture.spkiSha256.forEach { add(posture.host, it) } }
                    .build(),
            )
        }
        PinPosture.TofuWindow -> Unit
    }
    if (callTimeoutMillis != null) {
        builder.callTimeout(callTimeoutMillis, java.util.concurrent.TimeUnit.MILLISECONDS)
    }
    return builder.build()
}

/** Raises [BodySizeLimitInterceptor]'s ceiling for one request.
 *
 *  The default is sized for a JSON reply. Two routes legitimately carry far more — an attachment
 *  download and an armored OpenPGP payload — and before this existed a single constant had to be
 *  large enough for those, which meant every small JSON endpoint was also allowed to return tens
 *  of megabytes. Attach with `.tag(BodyLimit::class.java, BodyLimit(n))`. */
class BodyLimit(val maxBytes: Long)

internal class BodySizeLimitInterceptor(
    private val defaultMaxBytes: Long = MemoryBudget.JSON_RESPONSE_BYTES,
) : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        val maxBytes = request.tag(BodyLimit::class.java)?.maxBytes ?: defaultMaxBytes
        val response = chain.proceed(request)
        val body = response.body ?: return response
        // Content-Length, when the server bothers to send one, lets us refuse before reading a
        // single byte. An absent or lying header falls through to the streaming counter below.
        if (body.contentLength() > maxBytes) {
            body.close()
            throw IOException("Response body of ${body.contentLength()} bytes exceeds the $maxBytes byte limit")
        }
        return response.newBuilder().body(LimitedResponseBody(body, maxBytes)).build()
    }
}

private class LimitedResponseBody(
    private val delegate: ResponseBody,
    private val maxBytes: Long,
) : ResponseBody() {
    override fun contentType() = delegate.contentType()
    override fun contentLength() = delegate.contentLength()

    private val counting = object : ForwardingSource(delegate.source()) {
        private var seen = 0L
        override fun read(sink: Buffer, byteCount: Long): Long {
            val read = super.read(sink, byteCount)
            if (read != -1L) {
                seen += read
                if (seen > maxBytes) {
                    throw IOException("Response body exceeded the $maxBytes byte limit")
                }
            }
            return read
        }
    }

    private val limitedSource: BufferedSource = counting.buffer()

    override fun source(): BufferedSource = limitedSource
}
