#!/bin/sh
# Installs a release APK on the connected device and checks it reaches its first screens without
# crashing. Run by .github/workflows/release-smoke.yml.
#
# Driven from outside, the way a user reaches the app. An instrumented test APK cannot do this
# against a minified build: it shares the app's copies of androidx and Kotlin, R8 has already
# removed the members the test runner needs, and the runner crashes before the first test.
set -eu

apk=$1
pkg=$2

adb install -r "$apk" >/dev/null
adb logcat -c

# Waits up to 20 s for the window hierarchy to contain $1. The hierarchy, not a screenshot:
# FLAG_SECURE blanks screenshots, while uiautomator still reads views and their text.
expect() {
  i=0
  while [ "$i" -lt 20 ]; do
    if adb shell uiautomator dump /sdcard/smoke.xml >/dev/null 2>&1 &&
      adb shell cat /sdcard/smoke.xml | grep -q "$1"; then
      echo "ok: $2"
      return 0
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "FAILED: $2 (no '$1' on screen)" >&2
  adb shell cat /sdcard/smoke.xml >&2 || true
  return 1
}

failed=0

adb shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER -p "$pkg" >/dev/null
expect 'id/btnScanQr' 'the launcher opens pairing on a fresh install' || failed=1

# Parses the link, reads the pairing store and shows the confirmation naming the parsed host.
adb shell am force-stop "$pkg"
adb shell "am start -W -a android.intent.action.VIEW -p $pkg -d 'kypost://native-pair?sub=smoke&srv=https%3A%2F%2Fpair.example&pt=smoke'" >/dev/null
expect 'pair.example' 'a pairing link asks to confirm its server' || failed=1

adb shell am force-stop "$pkg"
adb shell am start -W -a android.intent.action.SENDTO -d mailto:smoke@example.com -p "$pkg" >/dev/null
expect 'id/composeToInput' 'mailto opens compose' || failed=1

adb logcat -d > /tmp/smoke-logcat.txt
if grep -A3 'FATAL EXCEPTION' /tmp/smoke-logcat.txt | grep -q "Process: $pkg,"; then
  grep -A20 'FATAL EXCEPTION' /tmp/smoke-logcat.txt >&2
  echo "FAILED: $pkg crashed" >&2
  failed=1
fi

test "$failed" -eq 0
