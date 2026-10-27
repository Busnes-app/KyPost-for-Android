#!/usr/bin/env bash
# Negative controls for the RFC 9180 adapter: each mutation of HpkeRecipient.kt must make the HPKE
# JVM tests fail. Usage: scripts/hpke-negative-controls.sh [extra gradle args]   (clean HpkeRecipient.kt)
set -u
cd "$(dirname "$0")/.."
file=app/src/main/java/org/kysecurity/mail/pgp/HpkeRecipient.kt
git diff --quiet HEAD -- "$file" || { echo "refusing: $file differs from HEAD"; exit 2; }
trap 'git checkout -q HEAD -- "$file"' EXIT

mutations=(
  'info dropped|s/"info_hash", info)/"info_hash", ByteArray(0))/'
  'mode_base -> mode_psk|s/MODE_BASE: Byte = 0x00/MODE_BASE: Byte = 0x01/'
  'KEM label|s/"eae_prk"/"eae_prk_"/'
  'schedule label|s/"base_nonce", context/"base_nonce_", context/'
  'version label|s/"HPKE-v1"/"HPKE-v2"/'
  'suite id aead|s/0x00, 0x01, 0x00, 0x02)/0x00, 0x01, 0x00, 0x01)/'
  'kem_context without pkRm|s/enc + pkRm, N_SECRET/enc, N_SECRET/'
)
results=app/build/test-results/testPlayDebugUnitTest
failed=0
for m in "${mutations[@]}"; do
  name=${m%%|*}
  git checkout -q HEAD -- "$file"
  sed -i "${m#*|}" "$file"
  if git diff --quiet HEAD -- "$file"; then echo "MUTATION DID NOT APPLY: $name"; failed=1; continue; fi
  rm -f "$results"/TEST-*Hpke*.xml
  if ./gradlew -q "$@" :app:testPlayDebugUnitTest --tests '*HpkeRecipientTest*' --tests '*EnrollmentCeremonyHpkeTest*' > /dev/null 2>&1; then
    echo "SURVIVED: $name"; failed=1
  elif grep -q '<failure' "$results"/TEST-*Hpke*.xml 2>/dev/null; then
    echo "killed: $name ($(grep -c '<failure' "$results"/TEST-*Hpke*.xml | paste -sd' '))"
  else
    echo "BUILD ERROR, not a test failure: $name"; failed=1
  fi
done
exit $failed
