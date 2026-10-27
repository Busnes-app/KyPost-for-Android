#!/usr/bin/env bash
# Negative controls for docs/STRONG-CRYPTO.md: each mutation of a production guard must make the
# JVM policy tests fail. Usage: scripts/strong-crypto-negative-controls.sh [extra gradle args]
set -u
cd "$(dirname "$0")/.."
main=app/src/main/java/org/kysecurity/mail
files=("$main/PairingAuthHeaders.kt" "$main/security/StrongTls.kt" "$main/pgp/PgpDecryptor.kt" "$main/pgp/PgpStrengthPolicy.kt")
git diff --quiet HEAD -- "${files[@]}" || { echo "refusing: guarded files differ from HEAD"; exit 2; }
trap 'git checkout -q HEAD -- "${files[@]}"' EXIT

mutations=(
  "client keeps platform TLS|$main/PairingAuthHeaders.kt|/\.sslSocketFactory(StrongTls.context(trust).socketFactory, trust)/d"
  "client offers legacy suites|$main/PairingAuthHeaders.kt|s/ConnectionSpec.RESTRICTED_TLS/ConnectionSpec.MODERN_TLS/"
  "RSA floor 1024|$main/security/StrongTls.kt|s/bitLength() >= 2048/bitLength() >= 1024/"
  "SHA-1 signatures accepted|$main/security/StrongTls.kt|s/if (trusted.dropLast(1).any { !signedStrongly(it.sigAlgOID) })/if (false)/"
  "empty path accepted|$main/security/StrongTls.kt|s/trusted.isEmpty() || //"
  "session cipher unchecked|$main/pgp/PgpDecryptor.kt|s/if (!PgpStrengthPolicy.archiveCipherAllowed(pked.getSymmetricAlgorithm(factory), strict = refuseLegacy))/if (false)/"
  "strict ignores key size|$main/pgp/PgpDecryptor.kt|s/if (refuseLegacy \&\& !(PgpStrengthPolicy/if (false \&\& !(PgpStrengthPolicy/"
  "strict keeps 64-bit ciphers|$main/pgp/PgpStrengthPolicy.kt|s/-> !strict/-> true/"
)
results=app/build/test-results/testPlayDebugUnitTest
failed=0
for m in "${mutations[@]}"; do
  IFS='|' read -r name file expr <<<"$m"
  git checkout -q HEAD -- "${files[@]}"
  sed -i "$expr" "$file"
  if git diff --quiet HEAD -- "$file"; then echo "MUTATION DID NOT APPLY: $name"; failed=1; continue; fi
  rm -f "$results"/TEST-*.xml
  if ./gradlew -q "$@" :app:testPlayDebugUnitTest --tests '*StrongTlsTest*' --tests '*PgpStrengthPolicyTest*' > /dev/null 2>&1; then
    echo "SURVIVED: $name"; failed=1
  elif grep -q '<failure' "$results"/TEST-*.xml 2>/dev/null; then
    echo "killed: $name ($(grep -c '<failure' "$results"/TEST-*.xml | sed 's|.*TEST-org.kysecurity.mail.||; s|.xml:| |' | paste -sd' '))"
  else
    echo "BUILD ERROR, not a test failure: $name"; failed=1
  fi
done
exit $failed
