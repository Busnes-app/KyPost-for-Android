package org.kysecurity.mail.pgp

internal class FakeVaultOpener(
    var outcome: OpenOutcome = OpenOutcome.Opened,
    var keyToHold: String? = TestPgpPrivateKey.ARMORED_PRIVATE,
    /** What is on disk, read without authentication; null when nothing. */
    var kindOnDisk: VaultRecordKind? = null,
) : VaultOpener {
    var opened = 0
    override fun sealedKind(): VaultRecordKind? = kindOnDisk
    override suspend fun open(): OpenOutcome {
        opened++
        if (outcome is OpenOutcome.Opened) keyToHold?.let { EnrollmentSession.put(it.toCharArray()) }
        return outcome
    }
}

internal class FakePayloadSource(var result: PgpPayloadResult) : PayloadSource {
    var fetched = 0
    override suspend fun fetch(mailbox: String, messageId: String): PgpPayloadResult {
        fetched++
        return result
    }
}

/** Defaults to ARMORED_MIME_MESSAGE: ARMORED_MESSAGE's plaintext has no MIME headers to parse. */
internal fun successPayload(
    encrypted: String = TestPgpPrivateKey.ARMORED_MIME_MESSAGE,
    signerKeys: List<SignerKey> = emptyList(),
    sender: String = "bob@example.com",
    resolvedSender: String = "bob@example.com",
) = PgpPayloadResult.Success(
    encryptedPayload = encrypted,
    signaturePayload = "",
    body = "",
    signedPartBase64 = "",
    signerKeys = signerKeys,
    sender = sender,
    resolvedSender = resolvedSender,
)

/** Signed but not encrypted, shaped as the server actually sends it: the verbatim signed octets in
 *  `signedPartBase64`, a detached signature over exactly those octets, and `body` EMPTY — the
 *  server empties `body` whenever it can produce the signed part, so the two never both arrive.
 *
 *  [signedPart] takes bytes, not a String, because that is what the signature covers. */
internal fun detachedSignedPayload(
    signedPart: ByteArray = TestPgpPrivateKey.DETACHED_SIGNATURE_BODY.toByteArray(Charsets.UTF_8),
    signaturePayload: String = TestPgpPrivateKey.ARMORED_DETACHED_SIGNATURE,
    body: String = "",
    signerKeys: List<SignerKey> = emptyList(),
    sender: String = "bob@example.com",
    resolvedSender: String = "bob@example.com",
) = PgpPayloadResult.Success(
    encryptedPayload = "",
    signaturePayload = signaturePayload,
    body = body,
    signedPartBase64 =
        if (signedPart.isEmpty()) "" else java.util.Base64.getEncoder().encodeToString(signedPart),
    signerKeys = signerKeys,
    sender = sender,
    resolvedSender = resolvedSender,
)
