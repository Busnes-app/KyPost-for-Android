package org.kysecurity.mail.security

import okhttp3.CertificatePinner
import java.security.cert.Certificate
import java.security.cert.X509Certificate

/** TOFU: the server cert pin is captured at pairing time and enforced on every later connect. */
object SpkiPinner {

    fun pinFor(certificate: Certificate): String = CertificatePinner.pin(certificate)

    /** The pin to store for an observed handshake chain: THE LEAF, and nothing else.
     *
     *  `CertificatePinner` passes when ANY chain member matches ANY configured pin. That single
     *  fact rules out every issuer in the chain, not just the root:
     *
     *  - A pinned public ROOT admits every certificate that root has ever issued or ever will.
     *  - A pinned public INTERMEDIATE is the same defect one link down, and it is the one this
     *    function used to have. For the ordinary deployment — a self-hosted relay behind Let's
     *    Encrypt — pinning R11 or E5 meant the pin asserted "issued by Let's Encrypt" and nothing
     *    more. Anyone who can answer for the host (DNS hijack, BGP, a hostile resolver, a
     *    compromised registrar) obtains their own certificate from the same CA in ninety seconds,
     *    for free, and it chains to the pinned intermediate. That is not a pin; it is WebPKI with
     *    extra steps and a UI that claims otherwise.
     *  - A pinned LEAF is a pin. It names one key.
     *
     *  A renewal that mints a new key matches no stored pin. [org.kysecurity.mail.push.TlsPinRollover]
     *  moves the pin to a new leaf only when the relay's identity key signed it; without that key
     *  every credentialed call fails until a pairing link or
     *  [org.kysecurity.mail.push.PushHomeViewModel.reconnectToServer] re-trusts the server, keeping
     *  the mailbox. A window of previously observed leaves was tried and could not work: a pin this
     *  device has never seen cannot be learned from a connection the pin itself rejects.
     *
     *  An entirely self-issued chain is a single self-signed server certificate, the
     *  self-hosted-relay case, and its leaf is also its anchor: pinning it is both correct and the
     *  only option, which falls out of taking the leaf without a special case. */
    fun pinsForChain(chain: List<Certificate>): Set<String> =
        chain.firstOrNull()?.let { setOf(pinFor(it)) }.orEmpty()

    /** A root is self-issued. Position in the chain is presentation; this is the property. */
    internal fun isTrustAnchor(certificate: Certificate): Boolean =
        (certificate as? X509Certificate)?.let { it.issuerX500Principal == it.subjectX500Principal } == true
}
