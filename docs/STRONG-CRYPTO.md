# Strong cryptography

[Product overview](../README.md) · [Security](../SECURITY.md) · [Assurance case](ASSURANCE-CASE.md)

What cryptography KyPost for Android uses, what it refuses, and the one interoperability
exception. Scope is code this repository produces and how it configures the libraries it calls.
Paths are relative to `app/src/main/java/org/kysecurity/mail/`.

The floor is NIST's minimum through 2030 (SP 800-57 Part 1, SP 800-131A): 112-bit symmetric
keys, 2048-bit RSA/DH, 224-bit elliptic curves, and a 224-bit hash wherever collision
resistance matters (signatures).

## Defaults

Nothing below needs configuring. Every row is what the app produces or accepts out of the box.

| Use | Algorithms and sizes | Where |
|---|---|---|
| TLS, every connection the app opens (relay API, pairing, KyIdentity sign-on, push register/pull, MFA, contacts, mail, OpenPGP payloads, wipe deregistration) | TLS 1.3 and 1.2 only. ECDHE key exchange with AES-GCM or ChaCha20-Poly1305 only (OkHttp `RESTRICTED_TLS`): no CBC, 3DES, RC4, static-RSA key exchange or SHA-1 MAC. Every certificate on the platform-validated path, anchor included, has RSA >= 2048 or EC >= 256 bits; every certificate below the anchor is signed with SHA-256/384/512 (RSA PKCS#1 or ECDSA). Platform trust (system anchors only), hostname checks, and the leaf SPKI pin after pairing all still apply. | `PairingAuthHeaders.kt` (`basePairingClient`), `security/StrongTls.kt`, `res/xml/network_security_config.xml` |
| KyIdentity sign-on token binding (`kypost-signon-pop/1`) | Ephemeral P-256 key per attempt (software JCA, never stored); its SPKI SHA-256 goes into the ID token via KyAuth, and the relay requires an ECDSA P-256 / SHA-256 signature over the relay origin and the token's SHA-256. | `signon/SignOnProof.kt` |
| New OpenPGP messages, drafts and Sent copies | AES-256, integrity-protected (SEIPD v1 with MDC), ZIP compression, SHA-256 signatures. Every recipient key and the signing key: RSA >= 2048, or ECDH/ECDSA/EdDSA/X25519/X448/Ed25519/Ed448 >= 224 bits, with a SHA-2/SHA-3 subkey binding. Any weak recipient refuses the whole send. | `pgp/PgpEncryptor.kt`, `pgp/PgpStrengthPolicy.kt` |
| OpenPGP keys | Not generated on the device. They arrive by enrollment (below); ECDH keys whose KDF is below SHA-256 or whose key wrap is not AES/Camellia do not parse (Bouncy Castle). | `pgp/KeyringImport.kt`, `pgp/PgpKeyring.kt` |
| OpenPGP signature trust | Only SHA-256/384/512 and SHA3-256/512 signatures from keys meeting the key floor can earn a badge; anything else is shown as **Signature not checked**. | `pgp/PgpDecryptor.kt`, `pgp/SignerBinding.kt` |
| OpenPGP decryption of received mail | Integrity protection is mandatory. v6 PKESK + SEIPDv2 (OCB) and RFC 9980 ID 35 decrypt through BC 1.87; ML-DSA-65+Ed25519 (ID 30) signatures verify. Session ciphers AES-128/192/256, Twofish and Camellia open; plaintext (NULL), single DES, SAFER and unknown ciphers are refused before any ciphertext is decrypted. Legacy ciphers and keys: see the exception below. | `pgp/PgpDecryptor.kt`, `pgp/PgpStrengthPolicy.kt` (`archiveCipherAllowed`) |
| Device enrollment envelope | v6 for new enrollment: HPKE mode_base, KEM 0x647A X-Wing (ML-KEM-768 + X25519), 1216-byte public key and 1120-byte encapsulation. Legacy v4/v5 still open with KEM 0x0010 DHKEM(P-256, HKDF-SHA256). Both use KDF 0x0001 HKDF-SHA256, AEAD 0x0002 AES-256-GCM; `info` binds `kypost-device-envelope/vN`, the device ID and the fingerprint, each length-prefixed; HPKE `aad` is empty. The retired custom v2/v3 formats are neither advertised nor opened: a delivered one is refused with "update your server". The X-Wing seed survives between operations only as AES-256-GCM ciphertext under a non-exportable StrongBox/TEE key with per-use user authentication; software-only protection is refused. Seed buffers are wiped; BC expanded key objects cannot be reliably erased. The P-256 agreement key remains non-exportable. Both live for one ceremony. SAS v2 binds every byte of the X-Wing public key. | `pgp/XWingEnvelope.kt`, `pgp/XWingEnrollmentKeys.kt`, `pgp/EnrollmentCipherPrompt.kt`, `pgp/HpkeRecipient.kt`, `pgp/DeviceEnvelope.kt` |
| Enrolled key at rest | AES-256-GCM under a Keystore key that requires the secure lock screen. | `pgp/EnrollmentVault.kt` |
| App PIN | PBKDF2-HMAC-SHA256, 150,000 iterations, 16-byte salt, 256-bit output, mixed with a Keystore HMAC-SHA256 pepper (StrongBox first). | `security/PinHasher.kt`, `security/CredentialCipher.kt` |
| Device secret wrap | AES-256-GCM under the PIN-derived, peppered key. | `security/CredentialCipher.kt` |
| Biometric unlock | Keystore RSA-2048, OAEP with SHA-256 (MGF1-SHA-1, the only MGF Android Keystore offers before API 35). | `security/BiometricUnlockVault.kt`, `security/CredentialEnvelope.kt` |
| Notification credential gate | Keystore AES-128-GCM (Keystore default size). | `security/AuthGateKey.kt` |
| Encrypted preferences | AndroidX Security: AES-256-GCM master key, AES-256-SIV keys, AES-256-GCM values. | `security/EncryptedPrefs.kt` |
| Mail database | SQLCipher 4 defaults (AES-256 with per-page HMAC-SHA512) under a random 32-byte key. | `security/DatabaseKey.kt`, `data/` |
| Password pairing (review path) | PBKDF2-HMAC-SHA256 at the server's work factor (100,000 to 12,000,000 iterations, else refused), then HKDF-SHA256. | `push/PasswordPairingClient.kt` |
| Identifiers and pins | SHA-256 (SPKI pins, KyAuth signer pins, enrollment codes, local ids). | `security/SpkiPinner.kt`, `signon/AuthenticatorPin.kt`, `pgp/DeviceEnrollmentCode.kt` |
| TLS pin rollover | Ed25519 signature by the relay identity key (32-byte key, Bouncy Castle `Ed25519Signer`) over host, leaf SPKI pin and issue time; a statement more than 24 h from the device clock is refused. | `push/TlsPinRollover.kt` |

## Refuse legacy encryption (strict configuration)

**Security → Encryption strength → Refuse legacy encryption.** Off by default. Turning it on
applies at once; turning it off asks for the app PIN when the lock is on. A security wipe keeps
the setting.

With it on, KyPost also refuses to decrypt received mail when:

- the decrypting key, or its primary, is below the key floor above (RSA < 2048 bits, elliptic
  curve < 224 bits, or ElGamal/DSA of any size), or
- the message's session cipher is IDEA, 3DES, CAST5 or Blowfish.

Nothing is deleted or re-encrypted; turning the setting off reads the same mail again. With it
on, no key length below the floor is used anywhere in the app (`EncryptedMessageReader.kt` reads
the setting per message; `security/CryptoPolicySettings.kt`).

## Interoperability exceptions

### Reading old mail with legacy keys and ciphers (default on)

**What:** by default, received mail still decrypts when it was encrypted to a historical key below
the floor (for example RSA-1024 or ElGamal) held in the user's keyring, or with a 64-bit-block
session cipher (IDEA, 3DES, CAST5, Blowfish).

**Why:** the sender chose those parameters, often years ago, and OpenPGP has no way to re-encrypt
a message the user already holds. Refusing would make the user's own archive unreadable with no
more secure alternative. GnuPG 1.x used CAST5 by default, and older keyrings carry RSA-1024 and
ElGamal subkeys.

**Risks:** a short key or 64-bit-block cipher gives the *sender's* message less protection than
the floor, so an attacker who captured that ciphertext in transit may recover it with enough
work. 64-bit blocks also have birthday-bound weaknesses on very large messages. Decrypting such a
message does not weaken anything else: the key and plaintext stay on the device.

**Mitigations:** these parameters are only ever *read*. Nothing new is encrypted, signed or
trusted with them (`PgpEncryptor` and `PgpStrengthPolicy` refuse weak keys for any new use, and
new messages always use AES-256). Integrity protection is still mandatory, so a tampered message
fails closed. Single DES, plaintext and unknown ciphers are refused even here. A signature from a
weak key never earns a badge. Users who do not need the archive turn on **Refuse legacy
encryption**.

### OpenPGP's own construction (SHA-1 MDC, CFB, PKCS#1 v1.5)

New messages use SEIPD v1: AES-256 in OpenPGP CFB mode, with a SHA-1 modification detection code,
and RSA recipients get the session key with PKCS#1 v1.5 padding. These are fixed by the OpenPGP
format that recipients support today. RFC 9580's SEIPD v2 (AEAD) is not supported by GnuPG, so
using it would make mail unreadable for most recipients. The MDC is not a signature: its security
does not rest on SHA-1 collision resistance, which is what makes SHA-1 unacceptable for
signatures. Integrity failures fail closed and zero the plaintext, including thrown AEAD failures during streaming or final verification (`PgpDecryptor.kt`). Bouncy
Castle's PKCS#1 v1.5 decoding is the library's own. Upgrade path: send SEIPD v2 when every
recipient key advertises it.

### Android Keystore OAEP (MGF1-SHA-1)

The biometric-unlock wrap uses RSA-OAEP with SHA-256 but MGF1-SHA-1, because Android Keystore
offers no other MGF digest before API 35 (minSdk is 31). MGF1 is a mask generator; SHA-1 there
does not rely on collision resistance and is permitted by SP 800-131A for non-signature use.

## Out of scope

Owned by someone else, so not claimed here:

- The mail server, KyPost-Server and anything they negotiate with other mail servers.
- Android itself: the Conscrypt/BoringSSL TLS stack (for example which TLS 1.2 handshake
  signature algorithms and groups it offers), the system trust store, Keystore and StrongBox.
- Google Play services: FCM transport, the QR code scanner module, and Play Billing in the
  `play` build's tip screen.
- The UnifiedPush distributor app and its connector library's RFC 8291 decryption.
- The Android System WebView, including remote images a user chooses to load into a message
  (sender-chosen hosts, no credentials) and webmail opened in a browser.
- Bouncy Castle, SQLCipher, OkHttp and AndroidX Security as libraries; this page covers only how
  KyPost configures and calls them.
- KyAuth, which signs KyIdentity tokens; KyPost only checks its signing certificate.

## Evidence

- `app/src/test/.../security/StrongTlsTest.kt`: key floor, SHA-2 signatures and whole-path
  judgement on real fixture certificates; every app client carries the policy and only modern
  suites. `SourceRulesTest.everyNetworkClientIsBuiltInOnePlace` fails if any other source file
  builds an HTTP client, opens a URL connection or a raw socket.
- `app/src/androidTest/.../security/StrongTlsDeviceTest.kt`: real Android TLS on loopback. Strong
  RSA and P-256 chains connect; an RSA-1024 leaf, an RSA-2047 intermediate, an RSA-2047 anchor
  that never appears on the wire, and a SHA-1-signed leaf are refused before any request, while
  the same weak key chains pass the platform alone. Leaf pins and hostname checks still decide.
  Fixtures come from `scripts/tls-fixtures.sh` and are test-only.
- `app/src/test/.../pgp/PgpStrengthPolicyTest.kt`: new messages read back as AES-256, integrity
  protected, SHA-256 signed; legacy ciphers open by default and close when strict; single DES is
  always refused; short decryption keys are refused when strict without touching the key.
- `app/src/test/.../signon/SignOnProofTest.kt`: the spec's golden vector (thumb, exact message
  bytes, recorded signature verifies) and a fresh-key round trip; `KyIdentitySignOnClientTest` pins
  the `{idToken, proofKey, proof}` request and verifies the sent proof.
- `scripts/strong-crypto-negative-controls.sh`: removes each guard in turn and requires the tests
  above to fail.

## Spec A read rollout

v1 keyrings remain readable; v2 replaces `activeFingerprint` with an `active` object containing
optional `v4` (40 hex) and `v6` (64 hex) fingerprints, with at least one present. Generation,
member list and complete fingerprint inventory retain their existing validation. Original bytes
are sealed without reserialization. Rings and v6 serialized envelopes have 512 KiB caps; member
and inventory counts stay at 16 and 256. v4/v5 transport bounds stay unchanged. This app has no
recovery-file importer; the server/browser recovery-file limit is owned there.

The enrollment-key publication reports `openpgp: ["v4", "v6", "rfc9980"]` beside its matching
envelope suite. This is a read-codec claim, never proof of durable enrollment. Classical sending
remains the default for a dual-active ring; v6 sending waits for P4's profile and split groups.
A different stored ring still requires explicit recovery; this change does not loosen replacement
safety. QR fingerprints carry all 40 or 64 hex digits.

`PqcInteropTest`, `EnrollmentCeremonyXWingTest` and `PgpKeyringV2Test` qualify the production paths
against pinned Go/WASM and RFC 9980 fixtures (`src/test/resources/kypost-server/PROVENANCE.md`).
`XWingEnrollmentKeysTest` and `EnrollmentCipherPromptLifecycleTest` cover Android refusal and
prompt cleanup; successful StrongBox/TEE per-use authentication still needs physical hardware.
