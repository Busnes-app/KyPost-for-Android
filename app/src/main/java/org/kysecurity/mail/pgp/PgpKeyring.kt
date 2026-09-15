package org.kysecurity.mail.pgp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.kysecurity.mail.MemoryBudget
import java.io.ByteArrayInputStream
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction

internal const val PGP_KEYRING_FORMAT = "kypost-pgp-keyring-v1"

/** The largest integer every peer (JavaScript included) represents exactly. */
private const val MAX_SAFE_GENERATION = (1L shl 53) - 1

private val RING_KEYS = setOf("format", "materialGeneration", "activeFingerprint", "keyFingerprints", "keys")
private val MEMBER_KEYS = setOf("fingerprint", "privateKey")
private val MEMBER_OPTIONAL_KEYS = setOf("revocationCertificate")
private val FINGERPRINT = Regex("[0-9A-F]{40}|[0-9A-F]{64}")

/** One primary key with its subkeys, exactly as the ring carried it. [armor] is the member's own
 *  bytes, kept so storage never has to be rebuilt from a re-exported key. */
internal class PgpKeyringMember(
    /** Uppercase, derived from the primary packet, not copied from the JSON. */
    val fingerprint: String,
    val ring: PGPSecretKeyRing,
    val armor: ByteArray,
    val revocationCertificate: String?,
) {
    override fun toString() = "PgpKeyringMember(redacted)"
}

/**
 * A validated `kypost-pgp-keyring-v1` ring. [original] is the exact plaintext that validated: it,
 * not a re-serialization, is what a later increment seals. [wipe] zeroes the byte copies this
 * holder owns; the JSON String and element tree the parser produced, and Bouncy Castle's packet
 * objects, are ordinary heap objects that cannot be zeroed and are simply dropped.
 */
internal class PgpKeyring(
    val original: ByteArray,
    val materialGeneration: Long,
    val activeFingerprint: String,
    /** Every primary and subkey fingerprint, uppercase, as derived from the packets. */
    val keyFingerprints: Set<String>,
    val members: List<PgpKeyringMember>,
) {
    val active: PgpKeyringMember get() = members.first { it.fingerprint == activeFingerprint }

    fun wipe() {
        original.fill(0)
        members.forEach { it.armor.fill(0) }
    }

    override fun toString() = "PgpKeyring(redacted)"
}

/**
 * Null for anything that is not a complete, self-consistent ring whose active key is
 * [expectedActiveFingerprint] — the fingerprint the caller committed to in the envelope AAD,
 * normalised the same way. Self-consistency alone is not enough: every AAD input is public, so a
 * ring that merely agrees with itself could name any active key its author controls. Every check
 * runs on the caller's temporary copy; nothing here touches the vault or the session. In order:
 * the plaintext bound, strict UTF-8, duplicate JSON keys, exact field set and types, the
 * inventory and its counts, then each member's packets — one unprotected private ring per entry
 * whose derived fingerprints, taken together, are exactly the inventory.
 */
internal fun parsePgpKeyring(plaintext: ByteArray, expectedActiveFingerprint: String): PgpKeyring? = runCatching {
    val expected = expectedActiveFingerprint.uppercase().filterNot { it.isWhitespace() }
    if (!FINGERPRINT.matches(expected)) return null
    if (plaintext.isEmpty() || plaintext.size > MemoryBudget.PGP_KEYRING_JSON_BYTES) return null
    val text = decodeStrictUtf8(plaintext) ?: return null
    if (jsonHasDuplicateKeys(text)) return null
    val root = Json.parseToJsonElement(text).jsonObject
    if (root.keys != RING_KEYS) return null
    if (root.string("format") != PGP_KEYRING_FORMAT) return null

    val generation = root["materialGeneration"]?.jsonPrimitive ?: return null
    if (generation.isString) return null
    val materialGeneration = generation.content.toLongOrNull() ?: return null
    if (materialGeneration !in 1..MAX_SAFE_GENERATION) return null

    val activeFingerprint = root.fingerprint("activeFingerprint") ?: return null
    if (activeFingerprint != expected) return null
    val inventory = root["keyFingerprints"]?.jsonArray ?: return null
    if (inventory.isEmpty() || inventory.size > MemoryBudget.PGP_KEYRING_FINGERPRINT_COUNT) return null
    val declared = HashSet<String>()
    for (entry in inventory) {
        val fingerprint = (entry as? JsonPrimitive)?.fingerprint() ?: return null
        if (!declared.add(fingerprint)) return null
    }

    val entries = root["keys"]?.jsonArray ?: return null
    if (entries.isEmpty() || entries.size > MemoryBudget.PGP_KEYRING_PRIMARY_COUNT) return null
    val members = ArrayList<PgpKeyringMember>(entries.size)
    val derived = HashSet<String>()
    for (entry in entries) {
        val member = parseMember((entry as? JsonObject) ?: return null) ?: return null
        if (!members.none { it.fingerprint == member.fingerprint }) return null
        members += member
        for (key in member.ring.publicKeys) {
            if (!derived.add(hex(key.fingerprint))) return null
        }
    }
    if (derived != declared) return null
    if (members.count { it.fingerprint == activeFingerprint } != 1) return null

    PgpKeyring(
        original = plaintext.copyOf(),
        materialGeneration = materialGeneration,
        activeFingerprint = activeFingerprint,
        keyFingerprints = derived,
        members = members,
    )
}.getOrNull()

private fun parseMember(o: JsonObject): PgpKeyringMember? {
    if (o.keys != MEMBER_KEYS && o.keys != MEMBER_KEYS + MEMBER_OPTIONAL_KEYS) return null
    val declared = o.fingerprint("fingerprint") ?: return null
    val revocation = if ("revocationCertificate" in o) o.string("revocationCertificate")?.takeIf { it.isNotEmpty() } ?: return null else null
    val armor = (o.string("privateKey") ?: return null).toByteArray(Charsets.UTF_8)
    // The legacy armor reader already enforces one armor block with nothing but whitespace
    // around it; a JSON entry must additionally hold exactly one ring.
    val ring = orderedSecretKeyRings(ByteArrayInputStream(armor))?.singleOrNull() ?: return null
    if (hex(ring.publicKey.fingerprint) != declared) return null
    // A public-only subkey has no secret packet at all; BC files it separately.
    if (ring.extraPublicKeys.hasNext()) return null
    for (secret in ring.secretKeys) {
        // Checked before any extraction so a passphrase-protected packet never reaches an S2K.
        if (secret.isPrivateKeyEmpty || secret.keyEncryptionAlgorithm != SymmetricKeyAlgorithmTags.NULL) return null
        secret.extractPrivateKey(null) ?: return null
        if (!secret.isMasterKey && !hasValidBindingSignature(ring.publicKey, secret.publicKey)) return null
    }
    return PgpKeyringMember(declared, ring, armor, revocation)
}

private fun JsonObject.string(key: String): String? =
    (this[key] as? JsonPrimitive)?.takeIf { it.isString }?.content

/** Uppercase for comparison; the reader is case-insensitive, and duplicates are caught after that. */
private fun JsonObject.fingerprint(key: String): String? = (this[key] as? JsonPrimitive)?.fingerprint()

private fun JsonPrimitive.fingerprint(): String? =
    takeIf { isString }?.content?.uppercase()?.takeIf { FINGERPRINT.matches(it) }

private fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02X".format(it) }

/** Malformed sequences are refused rather than replaced: a substituted character would let two
 *  different byte strings validate as one ring. */
internal fun decodeStrictUtf8(bytes: ByteArray): String? = runCatching {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
}.getOrNull()

/**
 * kotlinx keeps the last of two equal keys and says nothing; an inventory or member list stated
 * twice must not parse at all. Keys are compared as source text, so a key carrying any escape is
 * treated as a duplicate too: no accepted key needs one, and letting an escaped spelling through
 * would let kotlinx merge it with the plain one unseen. True on malformed input as well.
 */
internal fun jsonHasDuplicateKeys(text: String): Boolean = runCatching {
    val objects = ArrayDeque<HashSet<String>?>()
    var expectKey = false
    var i = 0
    while (i < text.length) {
        when (val c = text[i]) {
            '"' -> {
                var end = i + 1
                var escaped = false
                while (text[end] != '"') {
                    if (text[end] == '\\') { escaped = true; end++ }
                    end++
                }
                if (expectKey) {
                    if (escaped || !objects.last()!!.add(text.substring(i + 1, end))) return true
                    expectKey = false
                }
                i = end
            }
            '{' -> { objects.addLast(HashSet()); expectKey = true }
            '[' -> objects.addLast(null)
            '}', ']' -> objects.removeLast()
            ',' -> if (objects.last() != null) expectKey = true
            else -> Unit
        }
        i++
    }
    false
}.getOrDefault(true)
