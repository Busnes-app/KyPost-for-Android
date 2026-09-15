package org.kysecurity.mail.pgp

import org.kysecurity.mail.mail.ClientEncryptedDelivery
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.kysecurity.mail.mail.MailDraft
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import java.time.OffsetDateTime
import java.time.ZoneOffset

/** Discovery found a key whose fingerprint does not match the one pinned to that contact. */
private const val TIER_KEY_CHANGED = "key_changed"

/** Every way a client-encrypted send can end. One per row of the compose screen's exit table. */
internal sealed class ClientSendOutcome {
    data class Sent(val sentSaved: Boolean, val warning: String) : ClientSendOutcome()

    object Cancelled : ClientSendOutcome()
    object NotEnrolled : ClientSendOutcome()
    object NoSecureLockScreen : ClientSendOutcome()
    data class UnsealFailed(val message: String) : ClientSendOutcome()

    /** The account is not client-protected after all, so this is the wrong send path entirely. */
    object NotClientProtected : ClientSendOutcome()

    /** No mail account configured, so no valid `From` can be built. */
    object NoAccountAddress : ClientSendOutcome()

    /** A pinned key's fingerprint no longer matches what discovery returned. Deliberately distinct
     *  from [KeysMissing] and checked before it — see the KDoc on the check itself. */
    data class KeyChanged(val addresses: List<String>) : ClientSendOutcome()

    data class KeysMissing(val addresses: List<String>) : ClientSendOutcome()
    data class TooManyRecipients(val message: String) : ClientSendOutcome()
    data class ResolveFailed(val message: String) : ClientSendOutcome()
    data class EncryptFailed(val message: String) : ClientSendOutcome()
    data class SendFailed(val outcome: MailOutcome<*>) : ClientSendOutcome()
}

/** Recipient key lookup, behind an interface so this orchestrator takes no dependency on OkHttp,
 *  pairing credentials or a `Context`. */
internal fun interface RecipientKeyResolver {
    suspend fun resolve(addresses: List<String>): ResolveResult
}

/** The relay hop. Blocking, matching the rest of `MailSource`. */
internal fun interface ClientEncryptedTransport {
    fun send(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome>
}

/** Encrypts and signs one message on-device, then relays it. No Android imports, by contract. */
internal class ClientEncryptedSender(
    private val opener: VaultOpener,
    private val resolver: RecipientKeyResolver,
    private val transport: ClientEncryptedTransport,
    /** Keys this device pinned in person. The same lookup the read path gives strict precedence
     *  over the relay's; without it every outgoing key is whatever the relay chose to hand back.
     *  Deliberately not defaulted: a default here is a construction site that silently sends
     *  to the relay's key. */
    private val localKeys: LocalSignerKeyLookup,
    /** The address every delivery's `From` must carry, from `GET /api/pgp/bootstrap`'s
     *  `suggestedUserIDs[0]`. The relay compares each delivery's own header against it and answers
     *  403 on a mismatch. */
    private val accountAddress: String,
    private val now: () -> OffsetDateTime = { OffsetDateTime.now(ZoneOffset.UTC) },
    private val boundaryToken: () -> String = ::randomBoundaryToken,
) {

    suspend fun send(draft: MailDraft, sign: Boolean): ClientSendOutcome {
        val from = accountAddress.trim()
        if (from.isEmpty()) return ClientSendOutcome.NoAccountAddress

        val fields = splitRecipientFields(draft.to, draft.cc, draft.bcc)
        val addresses = fields.to + fields.cc + fields.bcc

        // Resolve BEFORE unlocking: a send that will be refused anyway must not cost a biometric prompt.
        val resolved = when (val result = resolver.resolve(addresses)) {
            is ResolveResult.Success -> result.results
            is ResolveResult.NotClientProtected -> return ClientSendOutcome.NotClientProtected
            is ResolveResult.TooMany -> return ClientSendOutcome.TooManyRecipients(result.message)
            is ResolveResult.Failed -> return ClientSendOutcome.ResolveFailed(result.message)
        }
        val byAddress = resolved.associateBy { it.address.lowercase() }

        // A broken pin outranks a missing key: key_changed can mean interception, so check it first.
        val changed = addresses.filter { byAddress[it.lowercase()]?.tier == TIER_KEY_CHANGED }
        if (changed.isNotEmpty()) return ClientSendOutcome.KeyChanged(changed)

        // The tier above is bookkeeping the relay controls; a pinned fingerprint is not.
        val pinned = applyPins(addresses, byAddress)
        if (pinned.mismatched.isNotEmpty()) return ClientSendOutcome.KeyChanged(pinned.mismatched)
        val keys = pinned.byAddress

        val missing = addresses.filter {
            val key = keys[it.lowercase()]
            key == null || !key.usable || key.publicKey.isBlank()
        }
        // There is no pickup fallback on this path and there must not be: the server-side one works
        // by storing the plaintext, which is the thing client-side protection exists to prevent.
        if (missing.isNotEmpty()) return ClientSendOutcome.KeysMissing(missing)

        if (!EnrollmentSession.isHeld()) {
            when (val outcome = opener.open()) {
                is OpenOutcome.Opened -> Unit
                is OpenOutcome.Cancelled -> return ClientSendOutcome.Cancelled
                is OpenOutcome.NotEnrolled -> return ClientSendOutcome.NotEnrolled
                is OpenOutcome.NoSecureLockScreen -> return ClientSendOutcome.NoSecureLockScreen
                is OpenOutcome.Failed -> return ClientSendOutcome.UnsealFailed(outcome.message)
            }
        }
        // Built once and shared by every delivery and the Sent copy, so no recipient can receive a
        // subtly different message from another.
        val protectedContent = buildProtectedContent(
            contentType = "${draft.mode.ifBlank { "html" }.asContentType()}; charset=utf-8",
            body = draft.body,
            subject = draft.subject,
            attachments = draft.attachments.map {
                OutgoingMimeAttachment(name = it.name, mimeType = it.mimeType, bytes = it.bytes)
            },
            boundaryToken = boundaryToken,
        ).toByteArray(Charsets.UTF_8)

        val date = rfc5322Date(now())

        // To and CC share one ciphertext; each BCC gets their own, so no BCC recipient's key id
        // appears in a packet another recipient can read.
        val groups = buildList {
            val shared = fields.to + fields.cc
            if (shared.isNotEmpty()) add(shared)
            fields.bcc.forEach { add(listOf(it)) }
        }

        // Scoped to withSigner: the explicit active signer, never a historical member; null means the app locked meanwhile.
        val ciphertexts = EnrollmentSession.withSigner { signer ->
            encryptAll(signer, sign, protectedContent, groups, keys, fields, from, date, boundaryToken)
        } ?: return ClientSendOutcome.NotEnrolled
        val (deliveries, sentCopyArmored) = when (ciphertexts) {
            is EncryptedBundle.Ok -> ciphertexts.deliveries to ciphertexts.sentCopy
            is EncryptedBundle.Failed -> return ClientSendOutcome.EncryptFailed(ciphertexts.message)
        }

        val outcome = transport.send(
            ClientEncryptedMessage(
                from = from,
                to = fields.to,
                cc = fields.cc,
                bcc = fields.bcc,
                deliveries = deliveries,
                sentCopy = wrapAsPgpMime(
                    envelope = OutgoingEnvelope(from = from, to = fields.to, cc = fields.cc, date = date),
                    armoredMessage = sentCopyArmored,
                    boundaryToken = boundaryToken,
                ),
                mode = draft.mode.ifBlank { "html" },
            ),
        )
        return when (outcome) {
            is MailOutcome.Success -> ClientSendOutcome.Sent(outcome.value.sentSaved, outcome.value.warning)
            else -> ClientSendOutcome.SendFailed(outcome)
        }
    }

    /** Relay keys with pinned material substituted in, and the addresses whose pin disagreed. */
    private data class PinnedRecipientKeys(
        val byAddress: Map<String, ResolvedRecipientKey>,
        val mismatched: List<String>,
    )

    /** Fingerprints are computed from the key bytes on both sides: the relay's `fingerprint` field
     *  is a claim beside the key with no cryptographic tie to it. A match encrypts to the PINNED
     *  bytes, not the relay's blob — matching fingerprints do not make the rest of a ring equal. */
    private suspend fun applyPins(
        addresses: List<String>,
        byAddress: Map<String, ResolvedRecipientKey>,
    ): PinnedRecipientKeys {
        val merged = byAddress.toMutableMap()
        val mismatched = mutableListOf<String>()
        for (address in addresses) {
            val lower = address.lowercase()
            val relayKey = merged[lower] ?: continue
            // A relay key that is already missing stays KeysMissing; it is not a changed key.
            if (!relayKey.usable || relayKey.publicKey.isBlank()) continue
            // "No pin recorded" and "a pin we hold and cannot verify" are opposite answers and must
            // not collapse. ContactMappers.toEntity stores a relay key verbatim even when compute()
            // rejects it, keeping the previous fingerprint, so keysFor CAN hand back a pin that will
            // not fingerprint — and treating that as never-pinned let a relay erase an in-person pin
            // by serving a broken key, then substitute any key it liked. A pin we cannot verify is
            // a refusal.
            val recorded = localKeys.keysFor(address).filter { it.publicKey.isNotBlank() }
            if (recorded.isEmpty()) continue
            val pins = recorded
                .mapNotNull { pin -> PgpFingerprint.compute(pin.publicKey)?.let { it to pin.publicKey } }
            if (pins.isEmpty()) {
                mismatched += address
                continue
            }
            // A relay key that will not fingerprint matches no pin, so it lands in `mismatched`.
            val relayFingerprint = PgpFingerprint.compute(relayKey.publicKey)
            val match = pins.firstOrNull { it.first == relayFingerprint }
            if (match == null) mismatched += address else merged[lower] = relayKey.copy(publicKey = match.second)
        }
        return PinnedRecipientKeys(merged, mismatched)
    }

    private sealed class EncryptedBundle {
        data class Ok(val deliveries: List<ClientEncryptedDelivery>, val sentCopy: String) : EncryptedBundle()
        data class Failed(val message: String) : EncryptedBundle()
    }

    @Suppress("LongParameterList")
    private fun encryptAll(
        signer: PGPSecretKeyRing?,
        sign: Boolean,
        protectedContent: ByteArray,
        groups: List<List<String>>,
        byAddress: Map<String, ResolvedRecipientKey>,
        fields: RecipientFields,
        from: String,
        date: String,
        boundaryToken: () -> String,
    ): EncryptedBundle {
        if (sign && signer == null) return EncryptedBundle.Failed("the signing key is unusable")
        val signingKey = signer.takeIf { sign }
        val deliveries = groups.map { recipients ->
            val keys = recipients.mapNotNull { byAddress[it.lowercase()]?.publicKey }
            val encrypted = PgpEncryptor.encrypt(protectedContent, keys, signingKey)
            if (encrypted !is EncryptResult.Ok) {
                return EncryptedBundle.Failed((encrypted as EncryptResult.Failed).message)
            }
            ClientEncryptedDelivery(
                recipients = recipients,
                ciphertext = wrapAsPgpMime(
                    envelope = OutgoingEnvelope(from = from, to = fields.to, cc = fields.cc, date = date),
                    armoredMessage = encrypted.armored,
                    boundaryToken = boundaryToken,
                ),
            )
        }

        // Encrypted to the public half of the key we just unsealed, never to anything the server
        // supplied. A hostile server handing back "your" public key would otherwise get a readable
        // copy of every message sent, with nothing on screen looking any different.
        val ownKey = signer?.let { PgpEncryptor.ownPublicKey(it) }
            ?: return EncryptedBundle.Failed("could not derive this account's own key")
        val sentCopy = PgpEncryptor.encrypt(protectedContent, listOf(ownKey), signingKey)
        if (sentCopy !is EncryptResult.Ok) {
            return EncryptedBundle.Failed((sentCopy as EncryptResult.Failed).message)
        }
        return EncryptedBundle.Ok(deliveries, sentCopy.armored)
    }

    private fun String.asContentType(): String = if (equals("plain", ignoreCase = true)) "text/plain" else "text/html"
}
