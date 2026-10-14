package org.kysecurity.mail.pgp

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.kysecurity.mail.mail.ClientEncryptedMessage
import org.kysecurity.mail.mail.MailOutcome
import org.kysecurity.mail.mail.MailSendOutcome
import java.io.ByteArrayOutputStream

internal class FakeRecipientKeyResolver(
    var result: ResolveResult = ResolveResult.Success(emptyList()),
) : RecipientKeyResolver {
    var calls = 0
    var lastAddresses: List<String> = emptyList()

    override suspend fun resolve(addresses: List<String>): ResolveResult {
        calls++
        lastAddresses = addresses
        return result
    }
}

internal class FakeClientEncryptedTransport(
    var outcome: MailOutcome<MailSendOutcome> = MailOutcome.Success(MailSendOutcome(true, "")),
) : ClientEncryptedTransport {
    val sent = mutableListOf<ClientEncryptedMessage>()

    override suspend fun send(message: ClientEncryptedMessage): MailOutcome<MailSendOutcome> {
        sent += message
        return outcome
    }
}

/** Builds a [ResolveResult.Success] where every address resolves to [publicKey] and is usable. */
internal fun resolvedAll(
    addresses: List<String>,
    publicKey: String,
    tier: String = "contact-verified",
    usable: Boolean = true,
) = ResolveResult.Success(
    addresses.map {
        ResolvedRecipientKey(
            address = it,
            publicKey = publicKey,
            fingerprint = "",
            tier = tier,
            usable = usable,
        )
    },
)

/** Pulls the armored OpenPGP block out of a PGP/MIME delivery, the way a recipient's client does. */
internal fun armorOf(delivery: String): String {
    val end = "-----END PGP MESSAGE-----"
    return delivery.substring(delivery.indexOf("-----BEGIN PGP MESSAGE-----"), delivery.indexOf(end) + end.length)
}

/** Contact keys pinned on this device, keyed by exact address the way `RoomLocalSignerKeys` is. */
internal class FakePinnedKeys(
    private val byAddress: Map<String, List<LocalSignerKey>> = emptyMap(),
) : LocalSignerKeyLookup {
    override suspend fun keysFor(address: String): List<LocalSignerKey> =
        byAddress[address.lowercase()].orEmpty()
}

/** The same primary key with every subkey removed: it fingerprints identically but, the primary
 *  being ed25519, cannot encrypt anything — so a delivery only opens if the pinned bytes were used. */
internal fun strippedOfSubkeys(armoredPublicKey: String): String {
    val ring = JcaPGPObjectFactory(
        PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
    ).nextObject() as PGPPublicKeyRing
    val stripped = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()
        .fold(ring) { acc, subkey -> PGPPublicKeyRing.removePublicKey(acc, subkey) }
    val out = ByteArrayOutputStream()
    ArmoredOutputStream(out).use { it.write(stripped.encoded) }
    return out.toString(Charsets.UTF_8.name())
}
