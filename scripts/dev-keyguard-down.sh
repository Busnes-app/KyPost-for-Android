#!/usr/bin/env bash
# Dismiss the CI PIN keyguard on the disposable emulator (mirrors ci.yml) and prove it is down.
set -u
export ANDROID_SERIAL="${ANDROID_SERIAL:-emulator-5554}"
adb shell settings put system screen_off_timeout 1800000
adb shell svc power stayon true
adb shell input keyevent 224
adb shell wm dismiss-keyguard
sleep 1
for i in 1 2 3 4 5 6 7 8 9 10; do
  adb shell dumpsys activity activities > /tmp/kg.txt 2>/dev/null
  grep -q "mKeyguardShowing=false" /tmp/kg.txt && grep -qE "ResumedActivity: ActivityRecord" /tmp/kg.txt && break
  adb shell input keyevent 224
  adb shell input swipe 540 1600 540 400
  adb shell input text 1234
  adb shell input keyevent 66
  sleep 3
done
adb shell dumpsys activity activities > /tmp/acts.txt 2>/dev/null || true
grep -oE "mKeyguardShowing=[a-z]+" /tmp/acts.txt | head -1
if grep -q "mKeyguardShowing=true" /tmp/acts.txt; then echo "keyguard still up" >&2; exit 1; fi
grep -qE "ResumedActivity: ActivityRecord" /tmp/acts.txt && echo "resumed activity present" || echo "WARNING: nothing resumed"
