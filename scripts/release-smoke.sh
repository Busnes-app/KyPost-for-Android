#!/bin/sh
# Installs a release APK on the connected device and checks it reaches its first screens without
# crashing. Run by .github/workflows/release-smoke.yml.
#
# Driven from outside, the way a user reaches the app. An instrumented test APK cannot do this
# against a minified build: it shares the app's copies of androidx and Kotlin, R8 has already
# removed the members the test runner needs, and the runner crashes before the first test.
set -u

apk=$1
pkg=$2

adb install -r "$apk" || exit 1
# The pairing screen asks for this on first start, and the system dialog would cover it.
adb shell pm grant "$pkg" android.permission.POST_NOTIFICATIONS
adb logcat -c

# Taps "Wait" on a system "isn't responding" dialog in the dump $1. A cold CI emulator's launcher
# sometimes stalls and its dialog covers the app. An ANR of this app still fails, via logcat below.
dismiss_anr_dialog() {
  bounds=$(sed -n 's/.*resource-id="android:id\/aerr_wait"[^>]*bounds="\[\([0-9]*\),\([0-9]*\)\]\[\([0-9]*\),\([0-9]*\)\]".*/\1 \2 \3 \4/p' "$1")
  [ -n "$bounds" ] || return 1
  # shellcheck disable=SC2086 # split the four coordinates
  set -- $bounds
  echo "dismissing a system ANR dialog"
  adb shell input tap $((($1 + $3) / 2)) $((($2 + $4) / 2))
}

# Says where a stalled app is stuck: its log, its Java stacks, and whether $1 shows up later.
# Release builds are not debuggable, but the google_apis image allows adb root, so debuggerd can
# read the stacks. Frames are R8-obfuscated; the workflow uploads mapping.txt to retrace them.
stall_report() {
  pid=$(adb shell pidof "$pkg" | tr -d '\r')
  [ -n "$pid" ] || { echo "stall report: $pkg is not running"; return; }
  echo "--- stall report: $pkg log"
  adb logcat -d --pid="$pid" | tail -100
  echo "--- stall report: $pkg Java stacks"
  adb root >/dev/null && adb wait-for-device && adb shell debuggerd -j "$pid" | head -600
  later=0
  while [ "$later" -lt 60 ]; do
    if adb shell uiautomator dump /sdcard/late.xml >/dev/null 2>&1 &&
      adb shell cat /sdcard/late.xml | grep -q "$1"; then
      echo "--- stall report: '$1' appeared $later s after the deadline (slow, not stuck)"
      return
    fi
    later=$((later + 1))
    sleep 1
  done
  echo "--- stall report: '$1' still absent 60 s after the deadline (stuck)"
}

# Waits up to 20 s for the window hierarchy to contain $1. The hierarchy, not a screenshot:
# FLAG_SECURE blanks screenshots, while uiautomator still reads views and their text.
expect() {
  i=0
  while [ "$i" -lt 20 ]; do
    adb shell rm -f /sdcard/smoke.xml
    if adb shell uiautomator dump /sdcard/smoke.xml >/tmp/smoke-dump.txt 2>&1; then
      adb shell cat /sdcard/smoke.xml >/tmp/smoke.xml
      if grep -q "$1" /tmp/smoke.xml; then
        echo "ok: $2"
        return 0
      fi
      dismiss_anr_dialog /tmp/smoke.xml
    fi
    i=$((i + 1))
    sleep 1
  done
  echo "FAILED: $2 (no '$1' on screen)"
  cat /tmp/smoke-dump.txt
  adb shell dumpsys activity activities | grep -E 'ResumedActivity|mKeyguardShowing'
  adb shell cat /sdcard/smoke.xml
  echo
  stall_report "$1"
  return 1
}

failed=0

# By component: `am start` resolves only CATEGORY_DEFAULT activities, and the launcher entry has none.
adb shell am start -W -n "$pkg/org.kysecurity.mail.MainActivity"
expect 'id/btnScanQr' 'the launcher opens pairing on a fresh install' || failed=1

# Parses the link, reads the pairing store and shows the confirmation naming the parsed host.
adb shell am force-stop "$pkg"
adb shell "am start -W -a android.intent.action.VIEW -p $pkg -d 'kypost://native-pair?sub=smoke&srv=https%3A%2F%2Fpair.example&pt=smoke'"
expect 'pair.example' 'a pairing link asks to confirm its server' || failed=1

adb shell am force-stop "$pkg"
adb shell am start -W -a android.intent.action.SENDTO -d mailto:smoke@example.com -p "$pkg"
expect 'id/composeToInput' 'mailto opens compose' || failed=1

adb logcat -d > /tmp/smoke-logcat.txt
if grep -A3 'FATAL EXCEPTION' /tmp/smoke-logcat.txt | grep -q "Process: $pkg,"; then
  grep -A20 'FATAL EXCEPTION' /tmp/smoke-logcat.txt
  echo "FAILED: $pkg crashed"
  failed=1
fi
if grep -q "ANR in $pkg" /tmp/smoke-logcat.txt; then
  grep -A10 "ANR in $pkg" /tmp/smoke-logcat.txt
  echo "FAILED: $pkg stopped responding"
  failed=1
fi

test "$failed" -eq 0
