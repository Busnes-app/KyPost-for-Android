# Purpose

Owns JVM unit tests for app logic that can run without device/emulator.

# Ownership

- Tests under `app/src/test/java/`

# Local Contracts

- Cover non-trivial logic changes with one focused regression test.
- Keep tests deterministic and fast.
- Encrypted-draft tests decrypt and verify a self-encrypted MIME message, pin the exact two-field
  wire shape, and prove no upload on pre-encryption failure. Custody routing must fail closed and
  re-probe enrollment after cached bootstrap reads.
- Reader data-image tests cover aggregate literal/CID limits in both image modes, including
  malformed-source and srcset bypasses; budget tests retain at least 4 MiB read headroom.
- `src/test/resources/kypost-server/` holds fixtures copied unchanged from KyPost-Server at the
  commit named in its `PROVENANCE.md`; `FixtureProvenanceTest` pins their SHA-256 and every scalar
  in them is public test data. `DeviceEnvelopeTest` pins ECDH, HKDF, AAD and ciphertext for both
  envelope versions against those vectors with Bouncy Castle point arithmetic, never a production
  sealer, and drives every v3 framing rejection. `PgpKeyringTest` parses the shared ring, decrypts
  both historical fixtures (one with a hidden recipient) through an independent Bouncy Castle
  path, and builds each negative member from the fixture keys (protected packet, public-only,
  two rings in one entry, grafted subkey, stripped subkey) rather than from generated keys.
- Lifecycle-owned plaintext tests use pure holders such as `OwnedAttachmentSave`; prove admission,
  source cleanup isolation, and wiping without an emulator or timing-dependent threads.
  `ReadOutcomeDeliveryTest` queues the worker and consumer independently to prove completed
  attachments are wiped when cancellation discards dispatcher delivery.
- A hand-rolled DAO fake must key its rows the way the real table does. `FakeEmailDao` is keyed on
  (folder, messageId) for that reason: keyed on the id alone it silently reproduced the
  folder-collision bug it was supposed to catch, and every test still passed. Where the SQL itself
  is the thing under test, the authority is an instrumentation test against real Room
  (`EmailDaoFolderScopeTest`, `EmailDaoClearDecryptedTest`).

# Work Guidance

- Prefer pure function tests for keyword tabbing/filtering behavior.
- Avoid network or Android framework dependencies in JVM unit tests.

# Verification

- Run `testPlayDebugUnitTest` after unit test updates — see root AGENTS.md: use `…PlayDebug`, not `…Debug`.

# Child DOX Index

- No child AGENTS.md files.
