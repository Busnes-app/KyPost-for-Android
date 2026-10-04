package org.kysecurity.mail.signon

import android.accounts.AccountManager
import android.content.Context
import android.content.pm.PackageManager
import org.kysecurity.mail.BuildConfig
import java.security.MessageDigest

/**
 * Only KyAuth may answer for the KyIdentity account type. The system routes by account type, so a
 * rogue app registering the same type would receive our getAuthToken and could phish the prompt.
 * Its token would fail at the relay, but the prompt is the user's, so refuse before asking.
 */
object AuthenticatorPin {
    const val ACCOUNT_TYPE = "org.kysecurity.identity"
    const val KYAUTH_PACKAGE = "org.kysecurity.authenticator"

    // KyAuth release signing certificate SHA-256 (Play App Signing uses the same key).
    internal val PINS: Set<String> = setOf(
        "52f61684029401fcb0137b334ad41907f83948fa1ec1377834f3b4291765fd7b",
    )

    fun trustedAuthenticator(context: Context): Boolean {
        val packages = AccountManager.get(context).authenticatorTypes
            .filter { it.type == ACCOUNT_TYPE }
            .map { it.packageName }
        val debug = BuildConfig.DEBUG_KYAUTH_CERT.takeIf { BuildConfig.DEBUG && it.isNotBlank() }
        return decide(packages, { pkg -> signingDigests(context.packageManager, pkg) }, debug)
    }

    internal fun decide(
        authenticatorPackages: List<String>,
        certDigestsFor: (String) -> Set<String>,
        extraDebugDigest: String?,
    ): Boolean {
        val pkg = authenticatorPackages.singleOrNull() ?: return false
        if (pkg != KYAUTH_PACKAGE) return false
        val allowed = if (extraDebugDigest != null) PINS + extraDebugDigest else PINS
        val actual = certDigestsFor(pkg)
        return actual.isNotEmpty() && allowed.containsAll(actual)
    }

    private fun signingDigests(pm: PackageManager, pkg: String): Set<String> = runCatching {
        val signing = pm.getPackageInfo(pkg, PackageManager.GET_SIGNING_CERTIFICATES).signingInfo
            ?: return@runCatching emptySet()
        if (signing.hasMultipleSigners()) return@runCatching emptySet()
        signing.signingCertificateHistory.map { sig ->
            MessageDigest.getInstance("SHA-256").digest(sig.toByteArray()).joinToString("") { "%02x".format(it) }
        }.toSet()
    }.getOrDefault(emptySet())
}
