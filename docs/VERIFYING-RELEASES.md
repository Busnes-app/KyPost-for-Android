# Verifying releases

[Product overview](../README.md) · [Security](../SECURITY.md) · [Development](DEVELOPMENT.md)

A KyPost GitHub release carries one APK, `kypost-vX.Y.Z.apk`, and its checksum,
`kypost-vX.Y.Z.apk.sha256`. The APK is the `github` channel (`org.kysecurity.mail.github`), built
for ARM phones only. This page shows how to check that an APK was signed with KyPost's release key
and which commit it says it was built from. It also explains why a rebuild from source does not
give the same bytes today.

The release workflow publishes every release as a **draft**. A draft is not a download. Use only a
release that the Releases page shows as published.

## What is signed, and by whom

- **The APK signature.** `release.yml` signs the APK with the KyPost release key (APK Signature
  Scheme v2). Before it publishes, it runs `apksigner` and refuses to publish unless the signer
  is the certificate stored in the `release` environment as `RELEASE_KEY_SHA256`. Android checks
  this signature on install and refuses an update signed by a different key. The certificate is:

  | | |
  |---|---|
  | Subject | `CN=Matthew Beacher, OU=Mobile Development, O=busnes.app, L=West Chester, ST=PA, C=US` |
  | SHA-256 | `6f78411156058c1d27d5160699b73c0f45de266282383d8ca4361592e03a6c8e` |

  The release notes do not repeat this digest; this page is where it is published. If an APK on
  the Releases page carries any other certificate, do not install it. Report it as described in
  [SECURITY.md](../SECURITY.md).
- **No build-provenance attestation.** Unlike KyAuth and the KyIdentity images, KyPost releases
  have no Sigstore attestation, so `gh attestation verify` has nothing to check.
- **The commit the APK names.** The Android Gradle plugin writes the commit it built from into
  `META-INF/version-control-info.textproto` inside the APK. The signature covers that file, so it
  is the release key holder's statement of the source. It is not independent proof, as an
  attestation would be.
- **The `.sha256` file** is not signed. It catches a damaged download and nothing more.
- **Google Play** builds (`org.kysecurity.mail`) are re-signed by Google under Play App Signing and
  carry a different certificate. **F-Droid** (`org.kysecurity.mail.fdroid`) is not published yet;
  when it is, F-Droid builds it and signs it with its own key. Nothing on this page applies to
  either.

## Verify a downloaded APK

You need `gh` (logged in), plus `apksigner` and `aapt2`, which are in the Android SDK's
`build-tools` directory. Name the version yourself.

```bash
v=<release version, e.g. 0.5.0>
gh release download v$v -R Busnes-app/KyPost-for-Android && sha256sum -c kypost-v$v.apk.sha256

# 1. Signed with the KyPost release key. Must print the SHA-256 above.
apksigner verify --print-certs kypost-v$v.apk | grep 'certificate SHA-256 digest'

# 2. The package and version you expect.
aapt2 dump badging kypost-v$v.apk | grep -o "^package: name=[^ ]* versionCode=[^ ]* versionName=[^ ]*"

# 3. The commit the APK names is the one the tag points at.
sha=$(gh api repos/Busnes-app/KyPost-for-Android/commits/refs/tags/v$v --jq .sha)
[ "$(unzip -p kypost-v$v.apk META-INF/version-control-info.textproto | sed -n 's/.*revision: "\(.*\)"/\1/p')" = "$sha" ] \
  && echo "OK: kypost-v$v.apk records commit $sha, which tag v$v points at"
```

Any failure means: do not install that APK. `apksigner verify` exits non-zero on a bad signature.
`keytool -printcert -jarfile` does **not** work here: the APK carries only a v2 signature, so
keytool answers "Not a signed jar file".

For v0.5.0 the three steps print the digest above, `org.kysecurity.mail.github` with
`versionCode='27' versionName='0.5.0'`, and commit `8f1acda1b9703bf1c4bc8b7c33428ac8577e1eef`.

## Rebuilding from source

A rebuild of the published APK does **not** give the same bytes today, and this page offers no
rebuild check. The reasons:

- The release build embeds the production Firebase configuration from the `GOOGLE_SERVICES_JSON`
  secret (`app/google-services.json` is gitignored). A rebuild from the public tree has different
  Firebase resources.
- The release key is needed to reproduce the signature. A rebuild can only be compared entry by
  entry against the published APK. That works only if every other input matches: the same JDK,
  Android SDK and `-PkypostArmOnlyApk` flag, and even the zlib library that compresses the ART
  baseline profiles. A KyAuth rebuild differed from its release in exactly those profiles.

The `fdroid` flavor has no Firebase and no secret inputs, so it is the one F-Droid can rebuild.
Whether two builds of it are identical has not been tested.

## What this does not prove

- That the source at the tag is safe. At best it shows which commit the key holder built.
- Anything about a Play install. Google signs those.
