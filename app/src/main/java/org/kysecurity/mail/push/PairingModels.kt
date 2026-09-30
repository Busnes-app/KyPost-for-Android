package org.kysecurity.mail.push

import java.net.URI
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Deliberately **not** `@Serializable`: it carries `deviceSecret` and `pairingToken`. */
data class PairingData(
    val subscriberId: String,
    val serverUrl: String,
    val registrationUrl: String,
    val pairingToken: String,
    val deviceId: String?,
    val deviceSecret: String?,
    val pairedAtEpochMs: Long,
    /** Leaf SPKI pin from the pairing link, in OkHttp's `sha256/<base64>` form, when the relay
     *  published one. Pins the registration call itself; see [org.kysecurity.mail.LinkPin].
     *  Not persisted: once registration succeeds the captured handshake pin supersedes it. */
    val spkiPin: String? = null,
) {
    /** Redacted: carries the device secret and pairing token. Enforced by `SourceRulesTest`. */
    override fun toString(): String = "PairingData(redacted)"
}

/** The account whose data a credential-only reconnect deliberately KEPT on this device.
 *
 *  [PushRepository.resetPairingCredential] removes the pairing proof and the TOFU pin while leaving
 *  mail, contacts, keys and the contact outbox in place, so "no pairing" stopped meaning "nothing
 *  here to lose". This is what names whose those survivors are. */
data class ReconnectExpectation(val subscriberId: String, val serverUrl: String)

/** Whether pairing [incoming] activates a DIFFERENT account than the data already on this device.
 *
 *  One answer for [PushSyncCoordinator.attemptPairing], which purges on true, and for the pairing
 *  confirmation dialog, which warns on it — split, the warning drifts from what actually happens.
 *  [reconnect] is consulted only when there is no [current] pairing: after a reconnect that is the
 *  sole record of the account the surviving mailbox belongs to. No pairing and no marker is a
 *  first-ever pairing, which must not purge anything. */
fun isAccountReplacement(
    incoming: PairingData,
    current: PairingData?,
    reconnect: ReconnectExpectation?,
): Boolean {
    val (subscriberId, serverUrl) = when {
        current != null -> current.subscriberId to current.serverUrl
        reconnect != null -> reconnect.subscriberId to reconnect.serverUrl
        else -> return false
    }
    return subscriberId != incoming.subscriberId || serverUrl != incoming.serverUrl
}

/** True when both are the same https origin. Userinfo makes both sides fail closed. */
internal fun sameOrigin(candidate: String, reference: String): Boolean {
    val a = pairingUrl(candidate) ?: return false
    val b = pairingUrl(reference) ?: return false
    return a.scheme.equals(b.scheme, ignoreCase = true) &&
        a.host.equals(b.host, ignoreCase = true) &&
        a.port == b.port
}

object NativeRegistrationEndpointResolver {
    sealed class Resolution {
        data class Resolved(val registrationUrl: String) : Resolution()
        object MissingServerUrl : Resolution()
    }

    /** A server-supplied [qrReg] wins only if it is the same origin as [qrServerUrl]. */
    fun resolve(qrReg: String?, qrServerUrl: String?): Resolution {
        val srv = qrServerUrl?.takeIf { it.isNotBlank() }?.trimEnd('/')
        val reg = qrReg?.takeIf { it.isNotBlank() }

        if (srv == null) {
            // With no server URL there is nothing to validate a reg URL against, so it cannot be
            // trusted either — this is an unusable pairing, not a reg-only one.
            return Resolution.MissingServerUrl
        }
        if (reg != null && sameOrigin(reg, srv)) return Resolution.Resolved(reg)
        return Resolution.Resolved("$srv/api/notifications/native/register")
    }
}

sealed class PairingParseResult {
    data class Success(val pairing: PairingData) : PairingParseResult()
    data class Error(val reason: String) : PairingParseResult()
}

object NativePairingDeepLinkParser {
    fun parse(link: String, nowEpochMs: Long = System.currentTimeMillis()): PairingParseResult {
        val uri = runCatching { URI(link.trim()) }.getOrNull()
            ?: return PairingParseResult.Error("Invalid deep link")

        if (!uri.scheme.equals("kypost", ignoreCase = true) ||
            !uri.host.equals("native-pair", ignoreCase = true)
        ) {
            return PairingParseResult.Error("Unsupported deep link")
        }

        // `kypost://native-pair` is BROWSABLE, so this string is attacker-chosen. The URI
        // constructor above rejects a malformed escape today, which is the only thing that keeps
        // URLDecoder from throwing — a guarantee that lives in another class and can change. Own it
        // here instead: this parser returns a refusal for every input, and never an exception.
        val query = runCatching { parseQuery(uri.rawQuery.orEmpty()) }.getOrNull()
            ?: return PairingParseResult.Error("Invalid deep link")

        val sub = query["sub"].orEmpty().trim()
        val srv = query["srv"].orEmpty().trim()
        val reg = query["reg"].orEmpty().trim().takeIf { it.isNotBlank() }
        val pt = query["pt"].orEmpty().trim()
        val pin = query["pin"].orEmpty().trim().takeIf { it.isNotBlank() }

        if (sub.isBlank()) return PairingParseResult.Error("Missing sub parameter")
        if (pt.isBlank()) return PairingParseResult.Error("Missing pairing token")
        if (srv.isBlank()) return PairingParseResult.Error("Missing server URL")
        // The server is arbitrary (self-hosted), so https-only is the one property we can enforce.
        if (!isHttpsUrl(srv)) {
            return PairingParseResult.Error("Server URL must use https")
        }
        if (reg != null && !isHttpsUrl(reg)) {
            return PairingParseResult.Error("Registration URL must use https")
        }
        // https alone is not enough: the dialog shows srv, so reg has to be the same server.
        if (reg != null && !sameOrigin(reg, srv)) {
            return PairingParseResult.Error("Registration URL must be on the same server as the server URL")
        }
        // Refuse rather than ignore. Dropping an unparseable pin would silently reopen the TOFU
        // window on the one request that carries the pairing token.
        val normalizedPin = pin?.let { org.kysecurity.mail.normalizeSpkiPin(it) }
        if (pin != null && normalizedPin == null) {
            return PairingParseResult.Error("Certificate pin is not a base64 SHA-256 SPKI hash")
        }

        // Resolved here, not left blank for callers to patch up. A blank `registrationUrl` is
        // meaningless — `readPairing` reads it as "no pairing at all" and `register` rejects it —
        // so emitting one made correctness depend on every consumer remembering to resolve it.
        val resolvedReg = when (val resolution = NativeRegistrationEndpointResolver.resolve(reg, srv)) {
            is NativeRegistrationEndpointResolver.Resolution.Resolved -> resolution.registrationUrl
            // Unreachable: `srv` is checked non-blank and https above. Kept as a refusal rather than
            // an `error()`, since the alternative is emitting the blank this change exists to remove.
            NativeRegistrationEndpointResolver.Resolution.MissingServerUrl ->
                return PairingParseResult.Error("Missing server URL")
        }

        return PairingParseResult.Success(
            PairingData(
                subscriberId = sub,
                serverUrl = srv,
                registrationUrl = resolvedReg,
                pairingToken = pt,
                deviceId = null,
                deviceSecret = null,
                pairedAtEpochMs = nowEpochMs,
                spkiPin = normalizedPin,
            ),
        )
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        return rawQuery.split('&')
            .mapNotNull { part ->
                val index = part.indexOf('=')
                if (index < 0) return@mapNotNull null
                val key = decode(part.substring(0, index))
                val value = decode(part.substring(index + 1))
                key to value
            }
            .toMap()
    }

    private fun decode(value: String): String {
        return URLDecoder.decode(value, StandardCharsets.UTF_8.name())
    }

    private fun isHttpsUrl(value: String): Boolean = pairingUrlHost(value) != null
}

/** The host a pairing URL will connect to, or null if we may never send credentials to it. */
internal fun pairingUrlHost(value: String): String? = pairingUrl(value)?.host

/** Parsed with OkHttp's [HttpUrl] — the parser that makes the request. https-only, no userinfo. */
internal fun pairingUrl(value: String): HttpUrl? {
    val url = value.trim().toHttpUrlOrNull() ?: return null
    if (!url.scheme.equals("https", ignoreCase = true)) return null
    if (url.username.isNotEmpty() || url.password.isNotEmpty()) return null
    if (url.host.isBlank()) return null
    // A query or fragment on a base URL is meaningless and, once a path is appended to it (see
    // [pairingEndpoint]), silently changes which path is actually requested.
    if (url.querySize > 0 || url.fragment != null) return null
    return url
}

/** Resolves [path] against the parsed base rather than concatenating strings. */
internal fun pairingEndpoint(serverUrl: String, path: String): HttpUrl? {
    val base = pairingUrl(serverUrl) ?: return null
    return base.resolve(base.encodedPath.trimEnd('/') + path)
}

/** The `kypost://native-pair` link [NativePairingDeepLinkParser] reads back; pure JVM so it is testable. */
internal fun pairingDeepLink(pairing: PairingData): String {
    fun enc(v: String) = URLEncoder.encode(v, StandardCharsets.UTF_8.name()).replace("+", "%20")
    val params = listOfNotNull(
        "sub" to pairing.subscriberId,
        "srv" to pairing.serverUrl,
        "reg" to pairing.registrationUrl,
        "pt" to pairing.pairingToken,
        pairing.spkiPin?.let { "pin" to it },
    )
    return "kypost://native-pair?" + params.joinToString("&") { (k, v) -> "$k=${enc(v)}" }
}
