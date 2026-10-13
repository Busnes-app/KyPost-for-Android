#!/usr/bin/env bash
# Installs the APK, locks orientation, and puts the status bar in demo mode (9:41, full bars).
# Usage: device-prep.sh <apk> [landscape|portrait]
set -euo pipefail
. "$(dirname "$0")/env.sh"
APK="$1"; ORIENT="${2:-portrait}"
adb install -r "$APK" | tail -1
adb shell pm grant org.kysecurity.mail android.permission.POST_NOTIFICATIONS || true
adb shell settings put system accelerometer_rotation 0
# Rotation 0 is the panel's natural orientation, which is landscape on tablet AVDs.
read -r w h <<<"$(adb shell wm size | grep -oE '[0-9]+x[0-9]+' | tail -1 | tr x ' ')"
natural=$([ "$w" -gt "$h" ] && echo landscape || echo portrait)
adb shell settings put system user_rotation "$([ "$ORIENT" = "$natural" ] && echo 0 || echo 1)"
adb shell settings put global sysui_demo_allowed 1
b() { adb shell am broadcast -a com.android.systemui.demo -e command "$@" >/dev/null; }
b enter
b clock -e hhmm 0941
b battery -e level 100 -e plugged false
b network -e wifi show -e level 4 -e fully true
b network -e mobile hide
b notifications -e visible false
b status -e volume hide -e bluetooth hide -e location hide -e alarm hide -e sync hide
