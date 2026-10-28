#!/usr/bin/env bash
# Negative controls for HPKE-only enrollment: each mutation re-admits a retired v2/v3 behaviour and
# must make the enrollment JVM tests fail. Every sed runs on both files and the files are restored
# from HEAD after each run. Usage: scripts/hpke-only-negative-controls.sh [extra gradle args]
set -u
cd "$(dirname "$0")/.."
files=(app/src/main/java/org/kysecurity/mail/pgp/DeviceEnvelope.kt app/src/main/java/org/kysecurity/mail/pgp/EnrollmentCeremony.kt)
git diff --quiet HEAD -- "${files[@]}" || { echo "refusing: ${files[*]} differ from HEAD"; exit 2; }
trap 'git checkout -q HEAD -- "${files[@]}"' EXIT

advertise='s/= listOf(ENVELOPE_VERSION_HPKE, ENVELOPE_VERSION_HPKE_KEYRING)/= listOf(2, 3, ENVELOPE_VERSION_HPKE, ENVELOPE_VERSION_HPKE_KEYRING)/'
refusal='s/if (delivery?.version in RETIRED_ENVELOPE_VERSIONS)/if (false)/'
mutations=(
  "advertise and parse v2/v3|$advertise"
  "no retired-delivery refusal|$refusal"
  "open v2/v3 again (both)|$advertise;$refusal"
  "quoted version tag|s/if (v.isString) return null/if (false) return null/"
)
results=app/build/test-results/testPlayDebugUnitTest
failed=0
for m in "${mutations[@]}"; do
  name=${m%%|*}
  git checkout -q HEAD -- "${files[@]}"
  sed -i "${m#*|}" "${files[@]}"
  if git diff --quiet HEAD -- "${files[@]}"; then echo "MUTATION DID NOT APPLY: $name"; failed=1; continue; fi
  rm -f "$results"/TEST-*.xml
  if ./gradlew -q "$@" :app:testPlayDebugUnitTest --tests '*DeviceEnvelopeTest*' --tests '*EnrollmentClientsTest*' \
      --tests '*EnrollmentCeremony*' > /dev/null 2>&1; then
    echo "SURVIVED: $name"; failed=1
  elif grep -q '<failure' "$results"/TEST-*.xml 2>/dev/null; then
    killers=$(awk -F'"' '/<testcase /{t=$2} /<failure/{print t}' "$results"/TEST-*.xml | sort -u | paste -sd' ')
    echo "killed: $name ($killers)"
  else
    echo "BUILD ERROR, not a test failure: $name"; failed=1
  fi
done
exit $failed
