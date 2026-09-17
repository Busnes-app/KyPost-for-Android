#!/usr/bin/env bash
# Focused JVM tests for the device-envelope work. Usage: scripts/dev-jvm-tests.sh [pattern ...]
# Prints compiler errors, failing tests and the build result only.
set -u
cd "$(dirname "$0")/.."
args=()
for p in "$@"; do args+=(--tests "$p"); done
if [ "${#args[@]}" -eq 0 ]; then
  args=(--tests '*EnrollmentClientsTest*' --tests '*EnrollmentReportOutcomeTest*' --tests '*EnrollmentStatusTest*'
        --tests '*EnrollmentCeremony*' --tests '*KeyringImportTest*' --tests '*KeyringSessionTest*'
        --tests '*ClientEncryptedSenderTest*' --tests '*RelayMailSourceTest*' --tests '*DeviceEnvelopeTest*')
fi
timeout 900 ./gradlew -q :app:testPlayDebugUnitTest "${args[@]}" > /tmp/dev-jvm-tests.log 2>&1
status=$?
grep -E '^e: |FAILED|tests completed|BUILD|Exception|expected|Assertion' /tmp/dev-jvm-tests.log | head -40
echo "gradle exit=$status"
