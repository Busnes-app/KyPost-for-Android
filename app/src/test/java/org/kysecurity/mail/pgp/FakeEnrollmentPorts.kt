package org.kysecurity.mail.pgp

/** `internal`, not `private`: top-level private classes collide across files in one package. */
/** The fingerprint the fake identity reports, and so the one a valid envelope's AAD must bind. */
internal const val FAKE_FINGERPRINT = "164D5B834E7FE927"

internal const val FAKE_PLAINTEXT =
    "-----BEGIN PGP PRIVATE KEY BLOCK-----\nnot a real key\n-----END-----"

/** Seals a real envelope the fake ports can open; the ECDH is covered by `EnrollmentKeyStoreTest`. */
internal fun sealEnvelope(
    keys: FakeEnrollmentKeys,
    deviceId: String = "dev-1",
    aadFingerprint: String = FAKE_FINGERPRINT,
    plaintext: String = FAKE_PLAINTEXT,
    version: Int = ENVELOPE_VERSION_LEGACY,
): String {
    val sharedSecret = requireNotNull(keys.sharedSecretResult)
    // v3 framing rejects an off-curve point before any ECDH runs, so the ephemeral point is a
    // real one (the generator); the fake keys ignore it when deriving the shared secret.
    val ephemeral = if (version == ENVELOPE_VERSION_KEYRING) {
        org.bouncycastle.asn1.x9.ECNamedCurveTable.getByName("secp256r1").g.getEncoded(false)
    } else {
        ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = 0x44 }
    }
    val key = hkdfSha256(
        ikm = sharedSecret,
        salt = keys.keystorePoint,
        info = envelopeDomain(version).toByteArray(Charsets.UTF_8),
        length = 32,
    )
    val iv = ByteArray(12) { 0x55 }
    val cipher = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
        init(
            javax.crypto.Cipher.ENCRYPT_MODE,
            javax.crypto.spec.SecretKeySpec(key, "AES"),
            javax.crypto.spec.GCMParameterSpec(128, iv),
        )
        updateAAD(deviceEnvelopeAad(version, deviceId, aadFingerprint))
    }
    val ct = cipher.doFinal(plaintext.toByteArray(Charsets.UTF_8))
    val b64 = java.util.Base64.getEncoder()
    return """
        {"v":${if (version == ENVELOPE_VERSION_LEGACY) "\"2\"" else "$version"},"alg":"ECDH-P256+HKDF-SHA256+A256GCM",
         "epk":"${b64.encodeToString(ephemeral)}",
         "iv":"${b64.encodeToString(iv)}",
         "ct":"${b64.encodeToString(ct)}"}
    """.trimIndent().replace("\n", "")
}

internal fun ringCount(armored: ByteArray): Int = orderedSecretKeyRings(armored.inputStream())!!.size

internal class FakeIdentitySource(private val result: IdentityCheck) : IdentitySource {
    var checkCalls = 0
        private set

    override suspend fun check(): IdentityCheck {
        checkCalls++
        return result
    }
}

/** [rawPublicKey] and [encodedPublicKey] deliberately disagree, so a wrong derivation fails. */
internal class FakeEnrollmentKeys(
    private val keyByte: Byte = 0x11,
    private val publishedByte: Byte = 0x22,
    private val minting: Boolean = true,
) : EnrollmentKeys {
    var newKeyPairCalls = 0
        private set
    var deleteCalls = 0
        private set
    var sharedSecretResult: ByteArray? = ByteArray(32) { 0x33 }
    private var exists = false

    /** Destroys the key mid-ceremony, as `SecurityWipe` and Hostile Location Protection both can. */
    var vanished = false

    /** A key that mints but whose public half cannot be read back: `getCertificate` returns nothing. */
    var encodingFails = false

    /** The point the code must be derived from. */
    val keystorePoint: ByteArray = ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = keyByte }

    /** A *different* point, standing in for "whatever was published". Nothing correct derives the
     *  code from this. */
    private val publishedPoint: ByteArray =
        ByteArray(65).also { it[0] = 0x04; for (i in 1..64) it[i] = publishedByte }

    override fun newKeyPair(): Boolean {
        newKeyPairCalls++
        exists = minting
        return minting
    }

    override fun rawPublicKey(): ByteArray? = keystorePoint.takeIf { exists && !vanished }

    override fun encodedPublicKey(): String? =
        publishedPoint.takeIf { exists && !vanished && !encodingFails }
            ?.let { java.util.Base64.getEncoder().encodeToString(it) }

    override fun sharedSecret(epk: ByteArray): ByteArray? = sharedSecretResult

    override fun deleteKeyPair(): Boolean {
        deleteCalls++
        exists = false
        return true
    }
}

/**
 * [fetchResults] is consumed one entry per poll; when it runs out, [fetchWhenExhausted] is returned
 * forever. That is how a test says "404 twice, then the envelope" or "404 until the window closes".
 */
internal class FakeEnrollmentTransport(
    private val deviceId: String? = "dev-1",
    var publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    private val fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    /** `var` so a test can change what a *later* window sees. A five-minute window is ~100 fetches,
     *  so "404 for the whole first window, then the envelope" is not expressible as a list. */
    var fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    var reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
) : EnrollmentTransport {
    val publishedKeys = mutableListOf<String>()
    val reported = mutableListOf<EnrollmentReport>()
    var fetchCalls = 0
        private set
    var durableReports = 0
        private set

    override suspend fun deviceId(): String? = deviceId

    override suspend fun publishKey(encodedPublicKey: String): EnrollmentCallResult {
        publishedKeys += encodedPublicKey
        return publishResult
    }

    override suspend fun fetchEnvelope(): EnrollmentCallResult {
        fetchCalls++
        return if (fetchResults.isEmpty()) fetchWhenExhausted else fetchResults.removeAt(0)
    }

    override suspend fun report(report: EnrollmentReport): EnrollmentCallResult {
        reported += report
        return reportResult
    }

    override fun enqueueDurableReport() {
        durableReports++
    }
}

internal class FakeDecryptedMailCache(private val cachedRows: Int = 3) : DecryptedMailCache {
    var clearCalls = 0
        private set
    var beforeClear: () -> Unit = {}

    override suspend fun clearServerDecryptedBodies(): Int {
        beforeClear()
        clearCalls++
        return cachedRows
    }
}

internal class FakeVaultSealer(
    var outcome: SealOutcome = SealOutcome.Sealed,
) : VaultSealer {
    var failure: Exception? = null
    /** A copy of what was handed over, taken before the ceremony zeroes the caller's array, so a
     *  test can prove the original was wiped without the fake's own copy being wiped too. */
    val received = mutableListOf<ByteArray>()

    /** The caller's array itself, kept by reference so a test can assert it was zeroed in place. */
    val handedArrays = mutableListOf<ByteArray>()

    /** The record kind each seal declared. */
    val kinds = mutableListOf<VaultRecordKind>()

    /** The acknowledgement each seal asked to store beside the record (null for legacy). */
    val acks = mutableListOf<EnrollmentReport.Keyring?>()

    /** Runs at the moment of sealing, so a test can observe what is (not yet) installed. */
    var onSeal: () -> Unit = {}

    override suspend fun seal(plaintext: ByteArray, kind: VaultRecordKind, ack: EnrollmentReport.Keyring?): SealOutcome {
        kinds += kind
        acks += ack
        onSeal()
        received += plaintext.copyOf()
        handedArrays += plaintext
        failure?.let { throw it }
        return outcome
    }
}

/** A clock the test drives: [sleep] advances the clock instead of sleeping. */
internal class FakeEnrollmentClock(
    // 1_680_000_000 / 120 is exactly 14_000_000, so the clock starts on a bucket boundary and a
    // test can count boundary crossings without arithmetic in its head.
    startEpochSeconds: Long = 1_680_000_000L,
    startElapsedMs: Long = 10_000L,
) : EnrollmentClock {
    var epochMs: Long = startEpochSeconds * 1_000
    var elapsedMs: Long = startElapsedMs
    val sleeps = mutableListOf<Long>()

    override fun epochSeconds(): Long = epochMs / 1_000

    override fun elapsedRealtimeMs(): Long = elapsedMs

    override suspend fun sleep(millis: Long) {
        sleeps += millis
        elapsedMs += millis
        epochMs += millis
    }
}

/** Every port, a recorded transcript of the states the ceremony emitted, and a factory. */
internal class FakePorts(
    identityResult: IdentityCheck = IdentityCheck.ClientProtected("164D5B834E7FE927"),
    deviceIdValue: String? = "dev-1",
    private val hostileLocation: Boolean = false,
    private val secureLockScreen: Boolean = true,
    publishResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    fetchResults: MutableList<EnrollmentCallResult> = mutableListOf(),
    fetchWhenExhausted: EnrollmentCallResult = EnrollmentCallResult.NotFound,
    reportResult: EnrollmentCallResult = EnrollmentCallResult.Ok,
    /** A keystore that refuses to mint — StrongBox and the TEE fallback both failing. */
    minting: Boolean = true,
    val previousVault: VaultOpener = FakeVaultOpener(outcome = OpenOutcome.NotEnrolled),
) {
    val identity = FakeIdentitySource(identityResult)
    val keys = FakeEnrollmentKeys(minting = minting)
    val transport = FakeEnrollmentTransport(
        deviceId = deviceIdValue,
        publishResult = publishResult,
        fetchResults = fetchResults,
        fetchWhenExhausted = fetchWhenExhausted,
        reportResult = reportResult,
    )
    val sealer = FakeVaultSealer()
    val mailCache = FakeDecryptedMailCache()
    val clock = FakeEnrollmentClock()

    /** Every state the ceremony emitted, in order. */
    val states = mutableListOf<EnrollmentUiState>()

    fun ceremony(): EnrollmentCeremony = EnrollmentCeremony(
        identity = identity,
        transport = transport,
        keys = keys,
        sealer = sealer,
        previousVault = previousVault,
        mailCache = mailCache,
        clock = clock,
        hostileLocationEnabled = { hostileLocation },
        hasSecureLockScreen = { secureLockScreen },
        onState = { states += it },
    )
}
