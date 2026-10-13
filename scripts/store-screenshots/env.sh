# Sourced by every harness script. Override any value from the environment.
# Secrets, TLS keys and raw shots live in $WORK, never next to these scripts.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT="${SHOTS_PROJECT:-kypost-tabletshots}"   # docker compose project (and volume prefix)
WORK="${SHOTS_WORK:-/tmp/$PROJECT}"
PORT="${SHOTS_PORT:-15867}"                     # relay on host loopback; emulator sees 10.0.2.2:$PORT
NET="${SHOTS_NET:-172.31.78}"                   # /24 for the compose network
R="https://127.0.0.1:$PORT"
MAIL_CTR="$PROJECT-mail-1"
# adb target; required so other running emulators are never touched (see `adb devices`).
export ANDROID_SERIAL="${ANDROID_SERIAL:?set ANDROID_SERIAL to the screenshot emulator, e.g. emulator-5554}"
mkdir -p -m 700 "$WORK"
