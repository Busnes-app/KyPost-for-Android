#!/usr/bin/env bash
# Taps the center of the Nth (default 1st) on-screen view whose resource-id, text or content-desc matches $1.
set -euo pipefail
adb shell uiautomator dump /sdcard/ui.xml >/dev/null 2>&1
b=$(adb exec-out cat /sdcard/ui.xml | grep -oE '<node [^>]*>' | grep -E "(resource-id=\"[^\"]*:id/$1\"|text=\"$1\"|content-desc=\"$1\")" | sed -n "${2:-1}p" | grep -oE 'bounds="\[[0-9]+,[0-9]+\]\[[0-9]+,[0-9]+\]"' || true)
[ -n "$b" ] || { echo "not found: $1" >&2; exit 1; }
read -r x1 y1 x2 y2 <<<"$(printf '%s' "$b" | grep -oE '[0-9]+' | tr '\n' ' ')"
adb shell input tap $(( (x1 + x2) / 2 )) $(( (y1 + y2) / 2 ))
