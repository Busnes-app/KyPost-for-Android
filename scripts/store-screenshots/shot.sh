#!/usr/bin/env bash
# Captures the current screen as raw shot <name> after checking no IME is up.
# Usage: shot.sh <name>     -> $WORK/raw/<name>.png
set -euo pipefail
. "$(dirname "$0")/env.sh"
mkdir -p "$WORK/raw"
if adb shell dumpsys input_method | grep -q 'mInputShown=true'; then echo "IME is showing; hide it first" >&2; exit 1; fi
adb exec-out screencap -p > "$WORK/raw/$1.png"
file "$WORK/raw/$1.png"
