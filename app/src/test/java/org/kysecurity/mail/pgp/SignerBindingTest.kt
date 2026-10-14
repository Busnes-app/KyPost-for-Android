package org.kysecurity.mail.pgp

import org.bouncycastle.openpgp.PGPPublicKeyRingCollection
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Test

class SignerBindingTest {

    // TestPgpKey.ARMORED's own key id, computed with the same parser [signatureStateFor] uses.
    private val testKeyId = signerKeyIdsOf(TestPgpKey.ARMORED).single()

    private fun sig(valid: Boolean = true, signerKeyId: Long = testKeyId) =
        RawSignature.Checked(signerKeyId, verified = valid)

    private fun key(
        address: String = "bob@example.com",
        verified: Boolean = false,
        source: String = "autocrypt",
        conflict: Boolean = false,
        publicKey: String = TestPgpKey.ARMORED,
    ) = SignerKey(listOf(address), publicKey, verified, source, conflict)

    @Test
    fun unsignedIsNone() {
        val state = signatureStateFor(RawSignature.Absent, listOf(key()))
        assertEquals(PgpSignatureState.NONE, state)
    }

    @Test
    fun aServerSuppliedVerifiedFlagCannotConfirmASigner() {
        val state = signatureStateFor(sig(), listOf(key(verified = true, source = "qr")))
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun onlyALocallyHeldKeyCanConfirmASigner() {
        val state = signatureStateFor(
            sig(),
            serverKeys = emptyList(),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true)),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, state)
    }

    @Test
    fun aLocalKeyWithAnOutstandingAlarmIsSeenBeforeNotConfirmed() {
        val state = signatureStateFor(
            sig(),
            serverKeys = listOf(key(verified = true, source = "qr")),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = false)),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    @Test
    fun aLocalKeyOverridesEveryServerClaim() {
        val relayKeyId = testKeyId + 1
        val state = signatureStateFor(
            sig(signerKeyId = relayKeyId),
            serverKeys = listOf(key(verified = true, source = "qr")),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true)),
        )
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aBadSignatureAgainstALocallyHeldKeyIsInvalid() {
        val state = signatureStateFor(
            sig(valid = false),
            serverKeys = emptyList(),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true)),
        )
        assertEquals(PgpSignatureState.INVALID, state)
    }

    @Test
    fun aRelayKeyWithNoLocalRecordIsNeverSeenBefore() {
        for (source in listOf("autocrypt", "qr", "manual")) {
            val state = signatureStateFor(sig(), listOf(key(verified = true, source = source)))
            assertEquals(source, PgpSignatureState.SIGNER_UNKNOWN, state)
        }
    }

    @Test
    fun onlyALocalKeyEarnsSeenBefore() {
        val state = signatureStateFor(
            sig(),
            serverKeys = emptyList(),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = false)),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, state)
    }

    @Test
    fun noKeysIsUnknown() {
        val state = signatureStateFor(sig(), emptyList())
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun changedKeyIsNeverJustUnknown() {
        val state = signatureStateFor(sig(), listOf(key(conflict = true, publicKey = "")))
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aBadSignatureAgainstABoundKeyIsInvalid() {
        val state = signatureStateFor(sig(valid = false), listOf(key()))
        assertEquals(PgpSignatureState.INVALID, state)
    }

    @Test
    fun aConflictOutranksAnOtherwiseGoodKeyForTheSameSender() {
        val state = signatureStateFor(
            sig(),
            listOf(key(verified = true, source = "manual"), key(conflict = true, publicKey = "")),
        )
        assertEquals(PgpSignatureState.KEY_CHANGED, state)
    }

    @Test
    fun aSignatureFromAnotherContactsKeyIsNeverAttributedToThisSender() {
        val notBobsKeyId = testKeyId + 1 // any id that is not TestPgpKey.ARMORED's own
        val state = signatureStateFor(
            sig(signerKeyId = notBobsKeyId),
            listOf(key(verified = true, source = "manual")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun aSignatureMatchingTheSendersBoundKeyIdIsStillVerified() {
        val seenBefore = signatureStateFor(
            sig(signerKeyId = testKeyId),
            serverKeys = emptyList(),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = false)),
        )
        assertEquals(PgpSignatureState.VERIFIED_SEEN_BEFORE, seenBefore)

        val confirmed = signatureStateFor(
            sig(signerKeyId = testKeyId),
            serverKeys = listOf(key(verified = true, source = "manual")),
            localKeys = listOf(LocalSignerKey(TestPgpKey.ARMORED, confirmed = true)),
        )
        assertEquals(PgpSignatureState.VERIFIED_CONFIRMED, confirmed)
    }

    @Test
    fun anUnparseableBoundKeyGrantsNoPass() {
        // signerKeyIdsOf returns empty rather than throwing, and an empty set matches no signerKeyId.
        val state = signatureStateFor(
            sig(signerKeyId = testKeyId),
            listOf(key(verified = true, source = "manual", publicKey = "this is not an OpenPGP key")),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun verifiedIsReadFromTheKeyThatActuallySignedNotAnyBoundKey() {
        val confirmedButDidNotSign =
            key(verified = true, source = "manual", publicKey = TestPgpPrivateKey.ARMORED_PUBLIC)
        val autocryptAndDidSign =
            key(verified = false, source = "autocrypt", publicKey = TestPgpKey.ARMORED)
        val state = signatureStateFor(
            sig(signerKeyId = testKeyId), // testKeyId belongs to TestPgpKey.ARMORED, not ARMORED_PUBLIC
            listOf(confirmedButDidNotSign, autocryptAndDidSign),
        )
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun anEncryptionOnlySubkeyIsNotASigner() {
        // TestPgpPrivateKey.ARMORED_PUBLIC's subkey (204EA3568BC889DD) is ENCRYPTION-only (flags 0C).
        val subkeyId = subkeyIdOf(TestPgpPrivateKey.ARMORED_PUBLIC)
        assertNotEquals(primaryKeyIdOf(TestPgpPrivateKey.ARMORED_PUBLIC), subkeyId)
        val boundKey = key(verified = true, source = "manual", publicKey = TestPgpPrivateKey.ARMORED_PUBLIC)
        val state = signatureStateFor(sig(signerKeyId = subkeyId), listOf(boundKey))
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    @Test
    fun anUnboundSubkeyGraftedOntoAGenuineKeyIsNotASigner() {
        val grafted = graftSubkeysOf(TestPgpPrivateKey.ARMORED_PUBLIC, onto = TestPgpKey.ARMORED)
        val graftedIds = signerKeyIdsOf(grafted)
        val foreignSubkeyId = subkeyIdOf(TestPgpPrivateKey.ARMORED_PUBLIC)
        assertEquals(
            "a subkey bound by a signature over a different primary must not be a signer",
            false,
            foreignSubkeyId in graftedIds,
        )
    }

    @Test
    fun theClientHoldsNoSenderParserOfItsOwn() {
        // signatureStateFor takes no sender argument, and never reads SignerKey.addresses.
        val keyWithUselessAddress = key(
            address = "this is not even a valid address, and it must not matter",
            verified = true,
            source = "manual",
        )
        val state = signatureStateFor(sig(), listOf(keyWithUselessAddress))
        assertEquals(PgpSignatureState.SIGNER_UNKNOWN, state)
    }

    /** [onto]'s primary plus [armoredPublicKey]'s subkeys; BouncyCastle checks no binding signature. */
    private fun graftSubkeysOf(armoredPublicKey: String, onto: String): String {
        var ring = PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(onto.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.next()
        publicKeysOf(armoredPublicKey).filter { !it.isMasterKey }.forEach { subkey ->
            ring = org.bouncycastle.openpgp.PGPPublicKeyRing.insertPublicKey(ring, subkey)
        }
        val out = java.io.ByteArrayOutputStream()
        org.bouncycastle.bcpg.ArmoredOutputStream(out).use { ring.encode(it) }
        return out.toString(Charsets.UTF_8.name())
    }

    private fun subkeyIdOf(armoredPublicKey: String): Long =
        publicKeysOf(armoredPublicKey).first { !it.isMasterKey }.keyID

    private fun primaryKeyIdOf(armoredPublicKey: String): Long =
        publicKeysOf(armoredPublicKey).first { it.isMasterKey }.keyID

    private fun publicKeysOf(armoredPublicKey: String) =
        PGPPublicKeyRingCollection(
            PGPUtil.getDecoderStream(armoredPublicKey.byteInputStream(Charsets.UTF_8)),
            BcKeyFingerprintCalculator(),
        ).keyRings.asSequence().flatMap { it.publicKeys.asSequence() }.toList()
}
