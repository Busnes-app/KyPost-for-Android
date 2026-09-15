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
# Override only to exercise this script's own reboot check (point it at /dev/null and the run
# must fail); a trigger that does not reboot the device never yields a pass.
TRIGGER="${VAULT_CRASH_TRIGGER:-/proc/sysrq-trigger}"
WORK="$(mktemp -d)"

phase() {
  local out="$WORK/$1.txt"
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
    adb shell dumpsys activity activities > "$WORK/keyguard.txt" 2>/dev/null || true
    if grep -q "mKeyguardShowing=false" "$WORK/keyguard.txt" && grep -qE "ResumedActivity: ActivityRecord" "$WORK/keyguard.txt"; then
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

boot_id() { adb shell cat /proc/sys/kernel/random/boot_id | tr -d '\r'; }

./gradlew -q :app:installPlayDebug :app:installPlayDebugAndroidTest
wait_for_boot
unlock
adb root > /dev/null
adb wait-for-device
if [ "$(adb shell id -u | tr -d '\r')" != "0" ]; then
  echo "adb root did not take; a non-rootable image cannot crash the kernel" >&2
  exit 1
fi
# Flush the installs themselves and outlast the ext4 commit interval, so the only write still in
# the journal window when the kernel dies is the record the vault claims durable.
adb shell sync
sleep 8
phase phase1SealsAKnownRecord

before="$(boot_id)"
echo "crashing the kernel"
# The shell dies with the kernel, so this exit status means nothing; the boot id below is the
# post-condition. Without it a trigger that silently does nothing turns this proof into a tautology.
adb shell "echo b > $TRIGGER" || true
sleep 5
wait_for_boot
after="$(boot_id)"
if [ -z "$before" ] || [ "$before" = "$after" ]; then
  echo "the device did not reboot (boot_id $before before, $after after); no crash was exercised" >&2
  exit 1
fi
unlock
phase phase2ReadsItBackAfterTheCrash
