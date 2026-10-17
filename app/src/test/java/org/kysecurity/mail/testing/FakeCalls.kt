package org.kysecurity.mail.testing

import org.kysecurity.mail.OfflineCall
import okhttp3.Call
import okhttp3.Callback
import okhttp3.CipherSuite
import okhttp3.Handshake
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.asResponseBody
import okhttp3.ResponseBody.Companion.toResponseBody
import okhttp3.TlsVersion
import okio.Buffer
import okio.Timeout
import okio.buffer
import java.io.ByteArrayInputStream
import java.io.IOException
import java.security.cert.CertificateFactory

/** Shared OkHttp [Call.Factory] fakes; `internal` because top-level `private` still clashes. */
internal class FakeCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        return FakeCall(request, responder(request))
    }
}

/** [FakeCallFactory] that also captures bodies; separate because reading a body consumes it. */
internal class BodyRecordingCallFactory(private val responder: (Request) -> Response) : Call.Factory {
    val requests = mutableListOf<Request>()
    val bodies = mutableListOf<String>()

    override fun newCall(request: Request): Call {
        requests.add(request)
        val buffer = Buffer()
        request.body?.writeTo(buffer)
        bodies.add(buffer.readUtf8())
        return FakeCall(request, responder(request))
    }
}

/** A factory whose calls always fail, for verifying a client's exception-to-result mapping without
 *  a real network or TLS stack. */
internal class ThrowingCallFactory(private val exception: Exception) : Call.Factory {
    override fun newCall(request: Request): Call = ThrowingCall(request, exception)
}

private class FakeCall(private val req: Request, private val response: Response) : OfflineCall(req) {
    private var executed = false
    private var canceled = false
    override fun execute(): Response {
        executed = true
        return response
    }
    override fun enqueue(responseCallback: Callback) = responseCallback.onResponse(this, response)
    override fun cancel() { canceled = true }
    override fun isExecuted(): Boolean = executed
    override fun isCanceled(): Boolean = canceled
    override fun clone(): Call = FakeCall(req, response)
}

private class ThrowingCall(private val req: Request, private val exception: Exception) : OfflineCall(req) {
    override fun execute(): Response = throw exception
    override fun enqueue(responseCallback: Callback) = responseCallback.onFailure(this, IOException(exception))
    override fun cancel() {}
    override fun isExecuted(): Boolean = false
    override fun isCanceled(): Boolean = false
    override fun clone(): Call = ThrowingCall(req, exception)
}

/** Canned JSON response; [headers] carries meaning outside the body, e.g. `Retry-After`.
 *
 *  [tlsHandshake] is null by default, which is what a fake factory honestly has: no TLS. Pass
 *  [testTlsHandshake] to exercise the code that captures a TOFU pin from what it observed. */
internal fun response(
    request: Request,
    body: String,
    code: Int,
    message: String = "OK",
    headers: Map<String, String> = emptyMap(),
    tlsHandshake: Handshake? = null,
): Response =
    Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message(message)
        .handshake(tlsHandshake)
        .body(body.toResponseBody("application/json".toMediaType()))
        .apply { headers.forEach { (name, value) -> header(name, value) } }
        .build()

/** Self-signed X.509 (CN=test) from: openssl req -x509 -newkey rsa:2048 -nodes -subj "/CN=test" */
private const val TEST_LEAF_PEM = """-----BEGIN CERTIFICATE-----
MIIC/zCCAeegAwIBAgIUE6Qe6XIm8Bqo7G0+cLuyzRKKj3swDQYJKoZIhvcNAQEL
BQAwDzENMAsGA1UEAwwEdGVzdDAeFw0yNjA3MjIxOTUzNDFaFw0zNjA3MTkxOTUz
NDFaMA8xDTALBgNVBAMMBHRlc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQDfTUaTJDPqXLJmGmXSKruwRXINM7aFz5Fl5Kigqa/i5ktwXUN9jkK9/zXA
lWZHY31lnCy4dOOJvyObIX/OPfRFxXixAH78s5MnucY9/iNCEpadB82hL/eidm9R
QJbf4DN53kITcdqed60Dv1UNhVDtYFAURA2bB7OWNZZ5BJzTIcXm8vo/9f1ASGff
eb702LoFhGqa2W7HlRiWNT+IybUJFC/YS5p60aVagqELs1a8dnD8lo+4PVSlKt8c
ChXs5CkAiQbxBq6IG96e36aguyQIM7NEvB3XzoG/9R6UDWwI5xM4U79b+8KzzjtC
TgYzMWAtpalZobJkiINqu2BBFPGHAgMBAAGjUzBRMB0GA1UdDgQWBBQ9GCHFPtA1
Qsn910vQG7Zq6WCfqDAfBgNVHSMEGDAWgBQ9GCHFPtA1Qsn910vQG7Zq6WCfqDAP
BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCFhY8GXovQiMWsMh9P
at9aEZaEW6jj4dEYunA6rdx8pIkNYsUInlZaf3e/r4gV1KYam1HjksqjZcIx/OLt
+PQSiliE85eo5yKkqjTUkAcfq949EK6Ro6E1vwsexWoKhkxr3pLD7BiVvHs8mYhC
nuDmvJ4vp9ZmHWd0I7nJVD7yNbFFo0dA1IudlPIwyRyWxs6sJ6nuX0VXsx0X27bK
Dz2zzpPDks3uI3gugUOsU1E4cgZaRmQXrGI0BeTY9xWKLwc6x0FVrTAk/t8WKdzq
mazZcakEoew6O+YDEZ4A2llo4FE/9P4vmou++GpXCvpdKQ9KX7ccjJ9enWCiF2Br
fdaR
-----END CERTIFICATE-----"""

/** A handshake presenting one real leaf, so `SpkiPinner` has something genuine to hash. */
internal val testTlsHandshake: Handshake by lazy {
    val leaf = CertificateFactory.getInstance("X.509")
        .generateCertificate(ByteArrayInputStream(TEST_LEAF_PEM.toByteArray()))
    Handshake.get(
        TlsVersion.TLS_1_3,
        CipherSuite.TLS_AES_128_GCM_SHA256,
        listOf(leaf),
        emptyList(),
    )
}

/** Body with real socket read semantics: one 8 KiB segment per read, unlike [response]'s Buffer. */
internal fun streamingResponse(
    request: Request,
    bytes: ByteArray,
    code: Int = 200,
    contentType: String = "application/octet-stream",
    headers: Map<String, String> = emptyMap(),
): Response {
    val backing = Buffer().write(bytes)
    val rawSource = object : okio.Source {
        override fun read(sink: Buffer, byteCount: Long): Long = backing.read(sink, byteCount)
        override fun timeout(): Timeout = Timeout.NONE
        override fun close() = backing.clear()
    }
    val builder = Response.Builder()
        .request(request)
        .protocol(Protocol.HTTP_1_1)
        .code(code)
        .message("OK")
        .body(
            rawSource.buffer().asResponseBody(contentType.toMediaType(), bytes.size.toLong()),
        )
    headers.forEach { (name, value) -> builder.header(name, value) }
    return builder.build()
}
