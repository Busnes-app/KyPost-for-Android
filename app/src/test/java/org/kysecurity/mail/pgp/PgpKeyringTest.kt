package org.kysecurity.mail.pgp

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags
import org.bouncycastle.openpgp.PGPCompressedData
import org.bouncycastle.openpgp.PGPEncryptedDataList
import org.bouncycastle.openpgp.PGPLiteralData
import org.bouncycastle.openpgp.PGPObjectFactory
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyEncryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream

class PgpKeyringTest {

    private val fixture = SharedFixtures.keyring()
    private val ring = fixture["ring"]!!.jsonObject
    private val ringBytes = ring.toString().toByteArray(Charsets.UTF_8)

    // ---- The shared fixture parses, and Bouncy Castle opens both historical ciphertexts. ----

    @Test
    fun theSharedRingParsesCompletely() {
        val parsed = requireNotNull(parsePgpKeyring(ringBytes))

        assertEquals(2L, parsed.materialGeneration)
        assertEquals("5F117951610CAF01500FA059CDE63F0EBEC934A2", parsed.activeFingerprint)
        assertEquals(2, parsed.members.size)
        assertEquals(ring["keyFingerprints"]!!.jsonArray.map { it.jsonPrimitive.content }.toSet(), parsed.keyFingerprints)
        assertEquals(parsed.activeFingerprint, parsed.active.fingerprint)
        assertEquals("3DA91B24C0BFAB595BEFE10D85ED094DCCE10615", parsed.members[1].fingerprint)
        assertArrayEquals("the original bytes are what gets sealed later", ringBytes, parsed.original)
        assertNull(parsed.members[0].revocationCertificate)
        assertEquals("PgpKeyring(redacted)", parsed.toString())
    }

    /** The v3 envelope vector carries this same ring as its plaintext: both fixtures agree. */
    @Test
    fun theV3VectorPlaintextIsTheSameRing() {
        val plaintext = SharedFixtures.deviceEnvelope()["vectors"]!!.jsonArray[1].jsonObject["plaintext"]!!.jsonPrimitive.content
        val parsed = requireNotNull(parsePgpKeyring(plaintext.toByteArray(Charsets.UTF_8)))
        assertEquals(requireNotNull(parsePgpKeyring(ringBytes)).keyFingerprints, parsed.keyFingerprints)
    }

    @Test
    fun historicalMailDecryptsWithARetainedMemberIncludingAHiddenRecipient() {
        val parsed = requireNotNull(parsePgpKeyring(ringBytes))
        val expected = fixture["plaintext"]!!.jsonPrimitive.content

        assertEquals(expected, decrypt(parsed, fixture["ciphertext"]!!.jsonPrimitive.content))
        assertEquals(expected, decrypt(parsed, fixture["hiddenCiphertext"]!!.jsonPrimitive.content))
        // The active member alone cannot: history is why every member is retained.
        val activeOnly = PgpKeyring(parsed.original, 2, parsed.activeFingerprint, parsed.keyFingerprints, listOf(parsed.active))
        assertNull(decrypt(activeOnly, fixture["ciphertext"]!!.jsonPrimitive.content))
    }

    @Test
    fun wipeZeroesTheBytesTheHolderOwns() {
        val parsed = requireNotNull(parsePgpKeyring(ringBytes))
        parsed.wipe()
        assertTrue(parsed.original.all { it == 0.toByte() })
        assertTrue(parsed.members.all { m -> m.armor.all { it == 0.toByte() } })
    }

    // ---- Fields and inventory. ----

    @Test
    fun fingerprintsCompareCaseInsensitivelyAndAreReportedUppercase() {
        val lowered = edit(
            "activeFingerprint" to JsonPrimitive(ring.string("activeFingerprint").lowercase()),
            "keyFingerprints" to JsonArray(ring["keyFingerprints"]!!.jsonArray.map { JsonPrimitive(it.jsonPrimitive.content.lowercase()) }),
        )
        val parsed = requireNotNull(parsePgpKeyring(lowered))
        assertEquals("5F117951610CAF01500FA059CDE63F0EBEC934A2", parsed.activeFingerprint)
        assertTrue(parsed.keyFingerprints.all { it == it.uppercase() })
    }

    @Test
    fun anOptionalRevocationCertificateIsPreservedVerbatim() {
        val cert = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: revocation\n-----END PGP PUBLIC KEY BLOCK-----\n"
        val parsed = requireNotNull(parsePgpKeyring(editMember(0, "revocationCertificate" to JsonPrimitive(cert))))
        assertEquals(cert, parsed.members[0].revocationCertificate)
        assertNull(parsePgpKeyring(editMember(0, "revocationCertificate" to JsonPrimitive(""))))
        assertNull(parsePgpKeyring(editMember(0, "revocationCertificate" to JsonPrimitive(1))))
    }

    @Test
    fun rejectsWrongFormatFieldsAndTypes() {
        assertNull("format", parsePgpKeyring(edit("format" to JsonPrimitive("kypost-pgp-keyring-v2"))))
        assertNull("extra top-level key", parsePgpKeyring(edit("comment" to JsonPrimitive("x"))))
        assertNull("missing key", parsePgpKeyring(JsonObject(ring - "keyFingerprints").toString().toByteArray()))
        assertNull("inventory not an array", parsePgpKeyring(edit("keyFingerprints" to JsonPrimitive("x"))))
        assertNull("keys not an array", parsePgpKeyring(edit("keys" to JsonPrimitive("x"))))
        assertNull("member not an object", parsePgpKeyring(edit("keys" to JsonArray(listOf(JsonPrimitive("x"))))))
        assertNull("active not a string", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive(1))))
        assertNull("active not hex", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive("Z".repeat(40)))))
        assertNull("active wrong length", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive("A".repeat(39)))))
        assertNull("array root", parsePgpKeyring("[]".toByteArray()))
        assertNull("empty", parsePgpKeyring(ByteArray(0)))
        assertNull("not json", parsePgpKeyring("ring".toByteArray()))
    }

    @Test
    fun rejectsEveryUnsafeGeneration() {
        for (bad in listOf("0", "-1", "2.0", "1e3", "9007199254740992", "\"2\"", "true", "null")) {
            assertNull("materialGeneration $bad", parsePgpKeyring(rawEdit("\"materialGeneration\":2", "\"materialGeneration\":$bad")))
        }
        assertEquals(9007199254740991L, parsePgpKeyring(rawEdit("\"materialGeneration\":2", "\"materialGeneration\":9007199254740991"))!!.materialGeneration)
        assertEquals(1L, parsePgpKeyring(rawEdit("\"materialGeneration\":2", "\"materialGeneration\":1"))!!.materialGeneration)
    }

    @Test
    fun rejectsAnInventoryThatDoesNotMatchThePackets() {
        val inventory = ring["keyFingerprints"]!!.jsonArray
        assertNull("missing subkey", parsePgpKeyring(edit("keyFingerprints" to JsonArray(inventory.drop(1)))))
        assertNull("extra fingerprint", parsePgpKeyring(edit("keyFingerprints" to JsonArray(inventory + JsonPrimitive("A".repeat(40))))))
        assertNull("duplicate after case normalization", parsePgpKeyring(edit("keyFingerprints" to JsonArray(inventory + JsonPrimitive(inventory[0].jsonPrimitive.content.lowercase())))))
        assertNull("empty inventory", parsePgpKeyring(edit("keyFingerprints" to JsonArray(emptyList()))))
        assertNull("non-string entry", parsePgpKeyring(edit("keyFingerprints" to JsonArray(inventory + JsonPrimitive(1)))))
        assertNull("over 256 entries", parsePgpKeyring(edit("keyFingerprints" to JsonArray(inventory + (1..253).map { JsonPrimitive("%040X".format(it)) }))))
    }

    @Test
    fun rejectsAnActiveMemberThatIsMissingOrAmbiguous() {
        val historical = ring["keys"]!!.jsonArray[1].jsonObject.string("fingerprint")
        assertNotNull("any member may be active", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive(historical))))
        assertNull("active is a subkey", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive("F8FF743DD85DDE3D427E8BA25CA9134FFE0FF9F4"))))
        assertNull("active absent", parsePgpKeyring(edit("activeFingerprint" to JsonPrimitive("A".repeat(40)))))
        val members = ring["keys"]!!.jsonArray
        assertNull("duplicate member", parsePgpKeyring(edit("keys" to JsonArray(members + members[0]))))
        assertNull("no members", parsePgpKeyring(edit("keys" to JsonArray(emptyList()))))
        assertNull("over 16 members", parsePgpKeyring(edit("keys" to JsonArray(List(17) { members[0] }))))
    }

    @Test
    fun rejectsDuplicateJsonKeysThatKotlinxWouldMerge() {
        val duplicated = rawEdit("\"materialGeneration\":2", "\"materialGeneration\":7,\"materialGeneration\":2")
        assertNull(parsePgpKeyring(duplicated))
        val duplicatedMember = rawEdit("\"privateKey\":", "\"fingerprint\":\"A\",\"privateKey\":")
        assertNull(parsePgpKeyring(duplicatedMember))
    }

    @Test
    fun duplicateKeyScanUnderstandsNestingAndEscapes() {
        assertFalse(jsonHasDuplicateKeys("""{"a":1,"b":{"a":2},"c":[{"a":3},{"a":4}]}"""))
        assertFalse(jsonHasDuplicateKeys("""{"a":"\"a\":1,\"a\":2","b":"}{"}"""))
        assertTrue(jsonHasDuplicateKeys("""{"a":1,"a":2}"""))
        assertTrue(jsonHasDuplicateKeys("""{"b":{"x":1,"x":2}}"""))
        assertTrue(jsonHasDuplicateKeys("""[{"k":1,"k":1}]"""))
        assertTrue("an escaped key spelling would merge unseen", jsonHasDuplicateKeys("""{"a":1,"\u0061":2}"""))
        assertTrue("no accepted key is ever escaped", jsonHasDuplicateKeys("""{"\"":1}"""))
        assertTrue("malformed counts as unsafe", jsonHasDuplicateKeys("""{"a":"unterminated"""))
        assertNull(parsePgpKeyring(rawEdit("\"format\":", "\"\\u0066ormat\":\"x\",\"format\":")))
    }

    @Test
    fun rejectsMalformedUtf8AndOversizedPlaintext() {
        assertNull(parsePgpKeyring(ringBytes + byteArrayOf(0xFF.toByte())))
        assertNull(parsePgpKeyring(byteArrayOf(0xC0.toByte(), 0x80.toByte()) + ringBytes))
        val padded = ring.toString().dropLast(1) + " ".repeat(128 * 1024) + "}"
        assertNull(parsePgpKeyring(padded.toByteArray(Charsets.UTF_8)))
        assertNull(decodeStrictUtf8(byteArrayOf(0xED.toByte(), 0xA0.toByte(), 0x80.toByte())))
    }

    // ---- Member packets. ----

    @Test
    fun rejectsAMemberWhoseDeclaredFingerprintIsNotItsPrimary() {
        val members = ring["keys"]!!.jsonArray.map { it.jsonObject }
        val swapped = JsonArray(
            listOf(
                JsonObject(members[0] + ("fingerprint" to members[1]["fingerprint"]!!)),
                JsonObject(members[1] + ("fingerprint" to members[0]["fingerprint"]!!)),
            ),
        )
        assertNull(parsePgpKeyring(edit("keys" to swapped)))
    }

    @Test
    fun rejectsPublicOnlyMaterial() {
        val secret = memberRing(0)
        val public = PGPPublicKeyRing(secret.publicKeys.asSequence().toList())
        assertNull(parsePgpKeyring(editMember(0, "privateKey" to JsonPrimitive(armor(public)))))
    }

    @Test
    fun rejectsTwoRingsInOneEntry() {
        val both = ByteArrayOutputStream().use { out ->
            ArmoredOutputStream(out).use { armor -> memberRing(0).encode(armor); memberRing(1).encode(armor) }
            out.toString(Charsets.UTF_8.name())
        }
        assertNull(parsePgpKeyring(editMember(0, "privateKey" to JsonPrimitive(both))))
    }

    /** Checked from the packet header, so no attacker-chosen passphrase KDF ever runs. */
    @Test
    fun rejectsAStillProtectedPrivatePacket() {
        val secret = memberRing(0)
        val encryptor = BcPBESecretKeyEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256, BcPGPDigestCalculatorProvider().get(org.bouncycastle.bcpg.HashAlgorithmTags.SHA256))
            .build("hunter2".toCharArray())
        val protected = PGPSecretKeyRing.copyWithNewPassword(secret, null, encryptor)
        assertNull(parsePgpKeyring(editMember(0, "privateKey" to JsonPrimitive(armor(protected)))))
    }

    @Test
    fun rejectsASubkeyWithoutABindingSignatureFromItsPrimary() {
        val a = memberRing(0)
        val foreignSubkey = memberRing(1).secretKeys.asSequence().first { !it.isMasterKey }
        val grafted = PGPSecretKeyRing.insertSecretKey(a, foreignSubkey)
        assertNull(parsePgpKeyring(editMember(0, "privateKey" to JsonPrimitive(armor(grafted)))))
    }

    @Test
    fun rejectsAMemberMissingItsSecretSubkeyPacket() {
        val a = memberRing(0)
        val subkey = a.secretKeys.asSequence().first { !it.isMasterKey }
        val stripped = PGPSecretKeyRing.removeSecretKey(a, subkey)
        // The public half survives as an extra public key; the ring is no longer complete.
        val withPublicOnlySubkey = PGPSecretKeyRing.insertOrReplacePublicKey(stripped, subkey.publicKey)
        assertNull(parsePgpKeyring(editMember(0, "privateKey" to JsonPrimitive(armor(withPublicOnlySubkey)))))
    }

    // ---- helpers ----

    private fun JsonObject.string(key: String) = this[key]!!.jsonPrimitive.content

    private fun edit(vararg edits: Pair<String, JsonElement>): ByteArray =
        JsonObject(ring.toMutableMap().apply { edits.forEach { (k, v) -> put(k, v) } }).toString().toByteArray(Charsets.UTF_8)

    private fun editMember(index: Int, vararg edits: Pair<String, JsonElement>): ByteArray {
        val members = ring["keys"]!!.jsonArray.toMutableList()
        members[index] = JsonObject(members[index].jsonObject.toMutableMap().apply { edits.forEach { (k, v) -> put(k, v) } })
        return edit("keys" to JsonArray(members))
    }

    private fun rawEdit(from: String, to: String): ByteArray {
        val text = ring.toString()
        require(text.contains(from)) { from }
        return text.replaceFirst(from, to).toByteArray(Charsets.UTF_8)
    }

    private fun memberRing(index: Int): PGPSecretKeyRing =
        requireNotNull(parsePgpKeyring(ringBytes)).members[index].ring

    private fun armor(ring: PGPSecretKeyRing): String = ByteArrayOutputStream().use { out ->
        ArmoredOutputStream(out).use { ring.encode(it) }
        out.toString(Charsets.UTF_8.name())
    }

    private fun armor(ring: PGPPublicKeyRing): String = ByteArrayOutputStream().use { out ->
        ArmoredOutputStream(out).use { ring.encode(it) }
        out.toString(Charsets.UTF_8.name())
    }

    /** Independent of `PgpDecryptor`: tries every retained private key, including for a hidden
     *  (all-zero) recipient key ID, which is what historical mail may carry. */
    private fun decrypt(keyring: PgpKeyring, armoredMessage: String): String? = runCatching {
        val factory = PGPObjectFactory(PGPUtil.getDecoderStream(ByteArrayInputStream(armoredMessage.toByteArray())), BcKeyFingerprintCalculator())
        val encrypted = generateSequence { factory.nextObject() }.filterIsInstance<PGPEncryptedDataList>().first()
        val secrets = keyring.members.flatMap { it.ring.secretKeys.asSequence().toList() }
        for (item in encrypted) {
            val pked = item as? PGPPublicKeyEncryptedData ?: continue
            val keyId = pked.keyIdentifier.keyId
            val candidates = if (keyId == 0L) secrets else secrets.filter { it.keyID == keyId }
            for (candidate in candidates) {
                val private = candidate.extractPrivateKey(null)
                val clear = runCatching { pked.getDataStream(BcPublicKeyDataDecryptorFactory(private)) }.getOrNull() ?: continue
                var obj = PGPObjectFactory(clear, BcKeyFingerprintCalculator()).nextObject()
                if (obj is PGPCompressedData) obj = PGPObjectFactory(obj.dataStream, BcKeyFingerprintCalculator()).nextObject()
                val literal = obj as PGPLiteralData
                return@runCatching literal.inputStream.readBytes().toString(Charsets.UTF_8)
            }
        }
        null
    }.getOrNull()
}
