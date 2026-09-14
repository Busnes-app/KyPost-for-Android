package org.kysecurity.mail.pgp

/** The ciphertext source, behind an interface so the orchestrator takes no Android dependency. */
internal interface PayloadSource {
    suspend fun fetch(mailbox: String, messageId: String): PgpPayloadResult
}

/** Every way reading an encrypted message can end. One per row of the spec's exit table. */
internal sealed class ReadOutcome {
    data class Decrypted(
        val body: DecryptedBody,
        val signature: PgpSignatureState,
        /** The mailbox the SERVER resolved from the From header, and the one the verdict is about.
         *  Rendered in place of the raw sender wherever a verdict is shown — the two are separable
         *  by an attacker. Empty when the server could not resolve one. */
        val resolvedSender: String,
    ) : ReadOutcome() {
        /** Redacted: the body is a decrypted message. Enforced by `SourceRulesTest`. */
        override fun toString(): String = "Decrypted(redacted)"
    }

    /** The key is not held and this call was not allowed to prompt. The screen offers Decrypt. */
    object NeedsUnlock : ReadOutcome()

    object Cancelled : ReadOutcome()
    object NotEnrolled : ReadOutcome()
    object NoSecureLockScreen : ReadOutcome()
    object TooLarge : ReadOutcome()
    object NotClientProtected : ReadOutcome()

    /** The server has the message but it carries no OpenPGP payload (404). Terminal — unlike a
     *  transport failure, retrying cannot change it, so the UI must not offer Retry. Reachable when
     *  the inbox flag said encrypted and the fetched message disagrees. */
    object NoEncryptedContent : ReadOutcome()

    /** Signed but not encrypted, and nothing readable came out: either the server produced neither
     *  the signed part nor a body, or the signed part would not parse as MIME.
     *
     *  Terminal for the same reason [NoEncryptedContent] is — the server populates `body` whenever
     *  it cannot produce the signed part, so both being empty is the message rather than a
     *  transport fault, and a re-fetch returns the same unparseable bytes. No Retry.
     *
     *  Its own outcome rather than [DecryptFailed], which the Mac client uses here: nothing on this
     *  path was ever encrypted, so "couldn't be decrypted on this device" names the wrong failure. */
    object NoReadableContent : ReadOutcome()

    data class UnsealFailed(val message: String) : ReadOutcome()
    data class FetchFailed(val message: String) : ReadOutcome()
    data class DecryptFailed(val message: String) : ReadOutcome()
}

/** Reads one client-protected message. No Android imports; the decrypted body is never stored. */
internal class EncryptedMessageReader(
    private val opener: VaultOpener,
    private val payloads: PayloadSource,
    /** This device's own answer to "whose key is this". Empty by default: the verdict caps lower. */
    private val localSignerKeys: LocalSignerKeyLookup = LocalSignerKeyLookup { emptyList() },
) {

    suspend fun read(
        mailbox: String,
        messageId: String,
        /** Display only, deliberately unread. Do not wire into the signature verdict; the server binds. */
        sender: String,
        /** False on an automatic attempt when the screen opens; true when the user tapped Decrypt.
         *  This is what keeps the biometric sheet tied to a deliberate action. */
        unlockIfNeeded: Boolean,
    ): ReadOutcome {
        if (!EnrollmentSession.isHeld()) {
            if (!unlockIfNeeded) return ReadOutcome.NeedsUnlock
            when (val outcome = opener.open()) {
                is OpenOutcome.Opened -> Unit
                is OpenOutcome.Cancelled -> return ReadOutcome.Cancelled
                is OpenOutcome.NotEnrolled -> return ReadOutcome.NotEnrolled
                is OpenOutcome.NoSecureLockScreen -> return ReadOutcome.NoSecureLockScreen
                is OpenOutcome.Failed -> return ReadOutcome.UnsealFailed(outcome.message)
            }
        }
        // Re-read rather than trusting the branch above: the app can lock between the unseal and
        // here, and lockNow() clears this holder.
        if (!EnrollmentSession.isHeld()) return ReadOutcome.NeedsUnlock

        val payload = when (val result = payloads.fetch(mailbox, messageId)) {
            is PgpPayloadResult.Success -> result
            is PgpPayloadResult.TooLarge -> return ReadOutcome.TooLarge
            is PgpPayloadResult.NotClientProtected -> return ReadOutcome.NotClientProtected
            is PgpPayloadResult.NoPayload -> return ReadOutcome.NoEncryptedContent
            is PgpPayloadResult.Failed -> return ReadOutcome.FetchFailed(result.message)
        }

        // The local answer, resolved first: a relay that lies about the address gets a lookup miss.
        val localKeys = runCatching { localSignerKeys.keysFor(payload.resolvedSender) }
            .getOrDefault(emptyList())

        // The server already narrowed signerKeys to the sender — do not re-narrow. Local keys go first.
        val offeredKeys =
            localKeys.map { it.publicKey } + payload.signerKeys.filter { !it.conflict }.map { it.publicKey }

        // Signed-but-not-encrypted.
        if (payload.encryptedPayload.isBlank()) {
            // The ONLY bytes a detached signature may be checked against. `body` is the server's
            // transfer-decoded render of the same part, so verifying against it could only ever
            // fail — which is what this branch used to do, and why it was marked unreachable.
            val signedPart = decodeSignedPart(payload.signedPartBase64)

            // The server ships both of these from one raw fetch or neither; empty means that fetch
            // failed, and it leaves `body` populated instead. That is a valid response, not an
            // error: show the message and claim nothing about its signature.
            if (signedPart.isEmpty() || payload.signaturePayload.isBlank()) {
                if (payload.body.isEmpty()) return ReadOutcome.NoReadableContent
                return ReadOutcome.Decrypted(
                    PgpMimeReader.read(payload.body.toByteArray(Charsets.UTF_8))
                        ?: DecryptedBody(html = null, plain = payload.body, protectedSubject = null),
                    PgpSignatureState.NONE,
                    payload.resolvedSender,
                )
            }

            val raw = offeredKeys.firstNotNullOfOrNull { armored ->
                PgpDecryptor.verifyDetached(
                    armoredPublicKey = armored,
                    body = signedPart,
                    armoredSignature = payload.signaturePayload,
                ).takeIf { it.valid }
            } ?: PgpDecryptor.verifyDetached(
                // Not the binding decision: this only yields a non-null RawSignature so the verdict can run.
                armoredPublicKey = offeredKeys.firstOrNull().orEmpty(),
                body = signedPart,
                armoredSignature = payload.signaturePayload,
            )
            // Rendered from the SAME bytes that were verified. Rendering `body` beside a verdict
            // computed from `signedPart` would show one message and vouch for another.
            //
            // The fallback is load-bearing, not defensive: a signed PLAIN-TEXT body carries no
            // blank line, so JavaMail consumes the whole thing as headers and PgpMimeReader
            // answers null for content that verified perfectly well. The Mac client calls this
            // unreadable; that would blank exactly the messages this commit set out to fix.
            //
            // Pinned to "plain" — unlike the `body` branch above, which leaves the mode empty so a
            // server-rendered HTML body still renders. Bytes that would not parse as MIME have not
            // earned markup treatment, and mode "" lets `bodyLooksLikeHtml` route them to the WebView.
            val parsed = PgpMimeReader.read(signedPart)
                ?: DecryptedBody(
                    html = null,
                    plain = String(signedPart, Charsets.UTF_8),
                    bodyMode = "plain",
                    protectedSubject = null,
                )
            return ReadOutcome.Decrypted(
                parsed,
                signatureStateFor(raw, payload.signerKeys, localKeys),
                payload.resolvedSender,
            )
        }

        // The key never leaves the holder's CharArray: withKey scopes it to this one call. Null
        // means the app locked between the check above and here, which is NeedsUnlock, not a
        // decryption failure.
        val result = EnrollmentSession.withKey { key ->
            PgpDecryptor.decrypt(key, payload.encryptedPayload, offeredKeys)
        } ?: return ReadOutcome.NeedsUnlock

        val decrypted = when (result) {
            is DecryptResult.Ok -> result
            // Deliberately does NOT clear EnrollmentSession: one message failing says nothing
            // about the held key, and clearing would re-prompt for every later message.
            is DecryptResult.Failed -> return ReadOutcome.DecryptFailed(result.message)
        }

        // Zeroed on every path out. The parsed body survives as Strings that cannot be wiped — they
        // are on their way to a WebView — but the raw decrypted MIME buffer is the largest copy of
        // the message in this process and it is trivially wipeable, so leaving it for the collector
        // (and for a heap dump taken any time before that) is a choice, not a constraint.
        val body = try {
            PgpMimeReader.read(decrypted.plaintext)
        } finally {
            java.util.Arrays.fill(decrypted.plaintext, 0)
        } ?: return ReadOutcome.DecryptFailed("this message could not be read once decrypted")

        val verdict = signatureStateFor(decrypted.signature, payload.signerKeys, localKeys)
        return ReadOutcome.Decrypted(
            body,
            // ponytail: nested MIME signatures are detected, not verified. Verify their exact
            // signed-part bytes before assigning any signer verdict to those wrappers.
            if (decrypted.signature is RawSignature.Absent) {
                if (body.hasDetachedSignature) PgpSignatureState.UNCHECKED else PgpSignatureState.UNSIGNED
            } else verdict,
            payload.resolvedSender,
        )
    }
}

/** Undecodable base64 reads as absent rather than as an error: a field the server could not fill
 *  and one it filled with rubbish leave the reader in the same place — unable to check, still able
 *  to show the message. `java.util.Base64`, not `android.util.Base64`, because this file holds no
 *  Android dependency. Strict, matching the server's `base64.StdEncoding`. */
private fun decodeSignedPart(base64: String): ByteArray {
    if (base64.isEmpty()) return ByteArray(0)
    return runCatching { java.util.Base64.getDecoder().decode(base64) }.getOrDefault(ByteArray(0))
}
