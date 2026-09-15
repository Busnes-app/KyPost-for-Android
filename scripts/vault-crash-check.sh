#!/usr/bin/env bash
# Proves a sealed vault record survives an unclean shutdown. Needs a rootable emulator (google_apis
# image) with lock PIN 1234, as CI arms it. Phase one seals a known record, the kernel is crashed
# through sysrq (no graceful shutdown, so nothing flushes on the way down), and phase two reads
# the record back after boot. Both phases are ordinary instrumentation tests selected by name.
set -euo pipefail
cd "$(dirname "$0")/.."

PKG=org.kysecurity.mail
RUNNER="$PKG.test/androidx.test.runner.AndroidJUnitRunner"
CLASS=org.kysecurity.mail.pgp.EnrollmentVaultCrashDurabilityTest

phase() {
  local out="/tmp/vault-crash-$1.txt"
  adb shell am instrument -w -e crashCheck true -e class "$CLASS#$1" "$RUNNER" > "$out" 2>&1 || true
  if ! grep -q "OK (1 test)" "$out"; then
    echo "$1 failed:" >&2
    cat "$out" >&2
    return 1
  fi
  echo "$1: ok"
}

wait_for_boot() {
  adb wait-for-device
  until [ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" = "1" ]; do sleep 2; done
  sleep 3
}

# Same dismissal as .github/workflows/ci.yml: credential-encrypted storage stays locked until the
# PIN is entered, so the app cannot even open its files directory before this.
unlock() {
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    adb shell dumpsys activity activities > /tmp/vault-crash-kg.txt 2>/dev/null || true
    if grep -q "mKeyguardShowing=false" /tmp/vault-crash-kg.txt && grep -qE "ResumedActivity: ActivityRecord" /tmp/vault-crash-kg.txt; then
      return 0
    fi
    adb shell input keyevent 224
    adb shell input swipe 540 1600 540 400
    adb shell input text 1234
    adb shell input keyevent 66
    sleep 3
  done
  echo "the keyguard is still up" >&2
  return 1
}

./gradlew -q :app:installPlayDebug :app:installPlayDebugAndroidTest
wait_for_boot
unlock
adb root > /dev/null
adb wait-for-device
# Flush the installs themselves and outlast the ext4 commit interval, so the only write still in
# the journal window when the kernel dies is the record the vault claims durable.
adb shell sync
sleep 8
phase phase1SealsAKnownRecord

echo "crashing the kernel"
adb shell 'echo b > /proc/sysrq-trigger' || true
sleep 5
wait_for_boot
unlock
phase phase2ReadsItBackAfterTheCrash
