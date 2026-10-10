# Replace deprecated `security-crypto` with Tink directly

**Status:** Planned, not implemented. Documentation only.
**Repo:** kypost-android
**Baseline:** Android `9bcaeb9` (PR #133 merged).
**Risk:** High. These files hold the pairing secret, the PIN verifier, the SQLCipher key and the
legacy enrollment vault. Losing one of them means re-pairing, a tripwire wipe, or loss of the
mail cache.

## Problem

`androidx.security:security-crypto` is deprecated in full, and the app pins `1.1.0`
(`gradle/libs.versions.toml:42`, `app/build.gradle.kts:546`). All production use goes through one
helper, `security/EncryptedPrefs.kt`. Imports are at `:9-10`, and `createEncryptedPrefs` builds a
`MasterKey` (AES256_GCM) plus `EncryptedSharedPreferences.create` with AES256_SIV keys and
AES256_GCM values at `:194-207`. Source files already carry the note "deprecated with no
replacement; swapping it is a format migration" (`EncryptedPrefs.kt:1`, `AppLockStore.kt:1`,
`SecurePairingStore.kt:1`).

There are four stores, and all of them open through `openEncryptedPrefs` (`EncryptedPrefs.kt:53`):

| File | Owner | Opened at |
| --- | --- | --- |
| `push_pairing_secure` | `push/SecurePairingStore.kt:20` | `:410` |
| `app_lock_secure` | `security/AppLockStore.kt:12` | `:271` |
| `db_key_secure` | `security/DatabaseKey.kt:10` | `:26` |
| `device_envelope_secure` (legacy, read-only) | `pgp/EnrollmentVault.kt:356` | `:346` |

All four are sealed under one Keystore alias, `ENCRYPTED_PREFS_MASTER_KEY_ALIAS`
(`EncryptedPrefs.kt:27`), which `SecurityWipe`'s last step destroys (`SecurityWipe.kt:355-359`).

Tink arrives today only transitively, as `tink-android` through `security-crypto`.
`UnifiedPush` already pulls the plain `tink` jar, which is excluded to avoid a class clash
(`app/build.gradle.kts:554-557`).

## Constraints that must survive

- **The open and reset contract stays as it is.** That covers the 3 attempts with 120 ms
  backoff (`EncryptedPrefs.kt:33-34`, `:60-71`), the three-proof `isUnrecoverableKeyset` truth
  table (`:97-109`), and `EncryptedStoreUnavailableException` meaning "unknown, never empty"
  (`:41`). The reason: `AppLockStore.tripwireBroken` turns an empty lock store into a full device
  wipe.
- **The protobuf-failure match keeps working after R8.** It matches by simple name
  (`EncryptedPrefs.kt:157-159`). `runtimeMatchedClassNames` keeps
  `com.google.crypto.tink.shaded.protobuf.InvalidProtocolBufferException`
  (`app/build.gradle.kts:404`).
- **`commit()` semantics stay.** They are load-bearing across the security code (comment at
  `app/build.gradle.kts:209`). In particular, the PIN-change staging relies on each file's own
  atomic commit (`app/src/main/AGENTS.md`, PIN change bullet).
- **SecurityWipe ordering does not change.** `app_lock_secure` stays in `PREFS_NAMES_RETAINED`
  (`SecurityWipe.kt:24-30`), and `androidxMasterKey` stays absolutely last.
- **Hostile Location Protection needs no special case.** No encrypted file is skipped or
  destroyed when HLP is on. HLP only swaps Room to in-memory (`DataRuntime.kt:14`). The flag
  itself is a plain, MAC'd prefs file that the wipe re-asserts (`SecurityWipe.kt:287-289`).
- **Backups are already off.** `allowBackup="false"` and `data_extraction_rules.xml` exclude
  every domain, so a new file name needs no new backup rule.

## Recommended design: keep the on-disk format, drop the wrapper

`EncryptedSharedPreferences` is a thin layer over Tink:
- Two Tink keysets are stored inside the prefs file itself, each wrapped by the Keystore master
  key through Tink's `AndroidKeysetManager`.
- Pref names are encrypted with deterministic AEAD (AES-SIV).
- Values are encrypted with AEAD (AES-GCM), tagged with a type.

Re-implementing that **same format** with `tink-android` declared directly removes the
deprecated dependency and **needs no data migration at all**. There is no copy step, no
crash window and no second file.

1. **Add the dependency.** Add `com.google.crypto.tink:tink-android` to `libs.versions.toml`.
   Remove `androidx-security-crypto` from `implementation` and keep it as
   `androidTestImplementation` only, as the compatibility oracle (step 4). Regenerate
   `gradle/verification-metadata.xml` in its own commit, as the toml header requires. Keep the
   UnifiedPush `tink` exclusion.
2. **Write a ~150-line replacement for `createEncryptedPrefs`.** Call it
   `security/TinkPrefs.kt`. It implements `SharedPreferences` and `Editor` (with `commit()`
   returning the underlying commit result) over a plain `getSharedPreferences(fileName)`:
   - It loads both keysets with `AndroidKeysetManager`, using the same pref names, the same
     prefs file, and a master key URI of `android-keystore://` + `ENCRYPTED_PREFS_MASTER_KEY_ALIAS`.
   - It encrypts names and values exactly as security-crypto 1.1.0 does.
   - `openEncryptedPrefs`, the retry loop and the reset path are unchanged; only the factory
     call is swapped.
3. **Keep the master key alias.** The `androidxMasterKey` wipe step, `keystoreAnswers()` and
   `masterKeyState()` stay valid. The step's name can be renamed later, but `ConcurrentWipeTest`
   and `WipeResurrectionTest` reference it.
4. **Prove format equality on a device, never by reading the library source alone.** The exact
   format is **UNPROVEN** here. It must be confirmed against the 1.1.0 sources and by the
   cross-check test below:
   - the keyset pref names `__androidx_security_crypto_encrypted_prefs_{key,value}_keyset__`
   - the file name as associated data for the name cipher
   - the encrypted name as associated data for the value cipher
   - the type-tag layout and the `__NULL__` sentinel
5. **Add a guard.** A `SourceRulesTest` rule: no `androidx.security.crypto` import under
   `app/src/main`.

### Fallback if step 4 fails: copy-migrate to a new file

Use this only if the format cannot be matched, for example if `AndroidKeysetManager` behaves
differently outside the wrapper. For each store, migrate on first open, inside the owner's
existing lock:

1. **Choose the authoritative source.** If `<name>_v2` contains `migrated=1`, it wins. Delete
   any surviving legacy file (idempotent), and stop.
2. **Discard a partial copy.** If `<name>_v2` exists without the marker, it is the leftover of a
   crashed copy: discard it.
3. **Open the legacy store** with the existing `openEncryptedPrefs`, so its classification and
   no-delete-on-unknown rule still apply. If the legacy file is absent, create an empty v2 with
   the marker.
4. **Copy and commit.** Copy every entry, then add `migrated=1` in the **same** `commit()`.
   One commit is one atomic file rename, so a crash before it leaves v2 discardable and a crash
   after it leaves v2 authoritative.
5. **Read back and compare** before deleting the legacy file.

Additional rules for the fallback:
- **Order.** Migrate `app_lock_secure` before `push_pairing_secure`, so `resolveDeviceSecret`
  never sees a staged secret without its verifier. Both files keep their staged and live keys
  verbatim.
- **Wipe.** `SecurityWipe.deleteAllSharedPrefs` and `PREFS_NAMES_RETAINED` must list both names
  for one release.
- **Tripwire.** `tripwireBroken` must read through the same resolver, so a missing legacy file
  after migration is never read as "PIN gone".

## Migration and rollback

- **Recommended path:** there is no migration. Rollback means reverting the dependency swap,
  and an older build reads the files unchanged, because the format is identical. That is the
  main reason to prefer it.
- **Fallback path:** a downgrade below the migrating release cannot read `_v2` files. Keep the
  legacy file until a later release, or accept that a downgrade means re-pairing. This is a
  decision for Yoshi.

## Tests

- **New `security/TinkPrefsCompatTest` (androidTest).**
  - Write with real `EncryptedSharedPreferences` and read with `TinkPrefs`, then the reverse.
    Cover every type (String, StringSet, Int, Long, Float, Boolean, null, removal).
  - Use the real key sets of `SecurePairingStore` and `AppLockStore`, including
    `pair_device_secret_pending_*`.
- **Unchanged and must stay green:**
  - `EncryptedPrefsResetTest`, including the empty-keyset and rubbish-keyset reset cases.
  - `UnrecoverableKeysetTest`, including `tinksRealParseFailureIsTheOneThisMatches`, which
    loads the shaded class by name. That class is now on the main classpath directly.
  - `SecurePairingStoreTest`, including `underlyingPrefsFile_doesNotContainPlaintextSecrets`
    and the corrupt-keyset case.
  - `SecurePairingStoreCredentialGateTest`, `PinChangeSecretRecoveryTest`, `AppLockStoreTest`.
  - `SecurityWipeTest` (`destroysTheAndroidxMasterKey`, `leavesNoEncryptedPrefsFileBehindEither`),
    `ConcurrentWipeTest`, `WipeResurrectionTest`.
- **Updated:** `FoldLockBehaviourTest`'s `AppLockSnapshot` opens `app_lock_secure` with its own
  copy of the builder (`:366-374`). Point it at the production factory.
- **Release check:** run a minified release on an emulator through a forced keyset-corruption
  reset, so the R8 name match is exercised in the build that ships.
- **Fallback path only:** add a kill-at-each-step migration test modelled on
  `PinChangeSecretRecoveryTest`.

## Risks

- **A format mismatch reads as an unrecoverable keyset and resets stores.** That is
  user-visible data loss. The compatibility test must run on the CI emulator matrix (31/34/36)
  before merge. This is also why the old library stays as a test oracle.
- **`AndroidKeysetManager` may itself be deprecated** in current Tink releases (**UNPROVEN**).
  If it is, the plan still holds, but the keyset-wrapping code moves in-house. That is about 40
  more lines using `KeysetHandle.read` with a Keystore AEAD.
- **Docs to update in the same PR:**
  - `app/AGENTS.md:34`
  - `app/src/main/AGENTS.md:14,489,540`
  - `README.md:22`
  - `SECURITY.md:133`
  - `Mobile_Mail_Relay.md:78`

## Open questions for Yoshi

1. Is the format-compatible reimplementation acceptable, or do you want a clean new format, at
   the cost of a migration and a no-downgrade release?
2. Should `security-crypto` stay as an `androidTestImplementation` oracle indefinitely, or be
   dropped after one release?
3. Should the `androidxMasterKey` wipe step be renamed now, or keep its name to avoid churn in
   the wipe tests?
