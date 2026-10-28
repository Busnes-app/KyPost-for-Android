# Changelog

## 0.5.1.1 — 2026-10-28

### Security

- Device enrollment accepts only RFC 9180 HPKE envelopes (v4/v5). The app advertises
  `envelopeVersions: [4, 5]` and the custom v2/v3 opener is removed. A server that delivers v2/v3
  gets "update your KyPost server" and nothing is saved or acknowledged. KyPost-Server #492 and
  later deliver v4/v5. Devices already enrolled are unaffected: the vault stores the opened key,
  never an envelope.
- Every connection now requires TLS 1.2 or 1.3 with an ECDHE AEAD cipher suite, RSA >= 2048
  or EC >= 256 keys on every certificate of the validated chain (trust anchor included) and
  SHA-2 certificate signatures. A server below that fails to connect.
- Received OpenPGP mail that uses plaintext, single DES, SAFER or an unknown session cipher is
  refused.
- New setting: Security → Encryption strength → **Refuse legacy encryption**. Off by default;
  when on, old mail that needs a key below RSA-2048 / 224-bit EC or a 64-bit cipher (IDEA,
  3DES, CAST5, Blowfish) is not opened. Nothing is deleted. Turning it off asks for the PIN.
- [docs/STRONG-CRYPTO.md](docs/STRONG-CRYPTO.md) lists every algorithm and key size the app
  uses and documents the old-mail exception.
