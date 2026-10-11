package org.kysecurity.mail.contacts

import org.bouncycastle.bcpg.ArmoredOutputStream
import org.bouncycastle.bcpg.HashAlgorithmTags
import org.bouncycastle.bcpg.PublicKeyAlgorithmTags
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters
import org.bouncycastle.openpgp.PGPKeyRingGenerator
import org.bouncycastle.openpgp.PGPPublicKey
import org.bouncycastle.openpgp.PGPPublicKeyRing
import org.bouncycastle.openpgp.PGPSecretKeyRing
import org.bouncycastle.openpgp.PGPSignature
import org.bouncycastle.openpgp.PGPSignatureGenerator
import org.bouncycastle.openpgp.PGPUtil
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPContentSignerBuilder
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider
import org.bouncycastle.openpgp.operator.bc.BcPGPKeyPair
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.security.SecureRandom
import java.util.Date

/** Keys and owner-made or forged revocations for the revocation tests. */
internal object RevocationTestKeys {
    /** Two encryption subkeys, a minute apart, so "the newest" is well defined. */
    @Suppress("DEPRECATION")
    fun secretRing(uid: String, subkeys: Int = 1): PGPSecretKeyRing {
        val rsa = RSAKeyPairGenerator().apply {
            init(RSAKeyGenerationParameters(BigInteger.valueOf(0x10001), SecureRandom(), 2048, 12))
        }
        val now = Date().time
        val primary = BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), Date(now - subkeys * 60_000L))
        return PGPKeyRingGenerator(
            PGPSignature.POSITIVE_CERTIFICATION,
            primary,
            uid,
            BcPGPDigestCalculatorProvider().get(HashAlgorithmTags.SHA1),
            null,
            null,
            BcPGPContentSignerBuilder(primary.publicKey.algorithm, HashAlgorithmTags.SHA256),
            null,
        ).apply {
            (1..subkeys).forEach {
                addSubKey(BcPGPKeyPair(PublicKeyAlgorithmTags.RSA_GENERAL, rsa.generateKeyPair(), Date(now - (subkeys - it) * 60_000L)))
            }
        }.generateSecretKeyRing()
    }

    fun publicRing(secret: PGPSecretKeyRing) = PGPPublicKeyRing(secret.publicKeys.asSequence().toList())

    fun public(secret: PGPSecretKeyRing) = armored(publicRing(secret).encoded)

    fun subkeys(secret: PGPSecretKeyRing): List<PGPPublicKey> = publicRing(secret).publicKeys.asSequence().filter { !it.isMasterKey }.toList()

    /** [owner]'s primary revoked by a signature from [signer]'s primary; [signer] other than
     *  [owner] makes it a forgery. */
    fun primaryRevoked(owner: PGPSecretKeyRing, signer: PGPSecretKeyRing): String {
        val ring = publicRing(owner)
        val signature = generator(signer, PGPSignature.KEY_REVOCATION).generateCertification(ring.publicKey)
        return armored(PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(ring.publicKey, signature)).encoded)
    }

    /** [owner]'s subkey [index] revoked by a signature from [signer]'s primary. */
    fun subkeyRevoked(owner: PGPSecretKeyRing, index: Int, signer: PGPSecretKeyRing): String {
        val ring = publicRing(owner)
        val subkey = ring.publicKeys.asSequence().filter { !it.isMasterKey }.toList()[index]
        val signature = generator(signer, PGPSignature.SUBKEY_REVOCATION).generateCertification(ring.publicKey, subkey)
        return armored(PGPPublicKeyRing.insertPublicKey(ring, PGPPublicKey.addCertification(subkey, signature)).encoded)
    }

    fun ring(armoredKey: String): PGPPublicKeyRing =
        JcaPGPObjectFactory(PGPUtil.getDecoderStream(armoredKey.byteInputStream(Charsets.UTF_8))).nextObject() as PGPPublicKeyRing

    private fun generator(signer: PGPSecretKeyRing, type: Int): PGPSignatureGenerator {
        val privateKey = signer.secretKey.extractPrivateKey(BcPBESecretKeyDecryptorBuilder(BcPGPDigestCalculatorProvider()).build(null))
        return PGPSignatureGenerator(BcPGPContentSignerBuilder(signer.secretKey.publicKey.algorithm, HashAlgorithmTags.SHA256))
            .apply { init(type, privateKey) }
    }

    fun armored(bytes: ByteArray): String {
        val out = ByteArrayOutputStream()
        ArmoredOutputStream(out).use { it.write(bytes) }
        return out.toString(Charsets.UTF_8.name())
    }
}
