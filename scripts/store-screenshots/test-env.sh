#!/usr/bin/env bash
# env.sh must refuse a work dir it does not own or that is a symlink: the dir holds TLS keys and
# passwords, and a planted one would capture them or redirect writes. Run: bash test-env.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
fail=0
source_env() { ( export ANDROID_SERIAL=test SHOTS_WORK="$1"; . "$HERE/env.sh" ) >/dev/null 2>&1; }
expect() { if source_env "$2"; then got=accepted; else got=refused; fi
  [ "$got" = "$1" ] && echo "ok   $1: $3" || { echo "FAIL $1 expected, got $got: $3"; fail=1; }; }

expect refused / "a dir owned by another user (root)"
mkdir "$T/real"; ln -s "$T/real" "$T/link"
expect refused "$T/link" "a symlink"
expect accepted "$T/fresh" "a new dir"
[ "$(stat -c %a "$T/fresh")" = 700 ] && echo "ok   new dir is mode 700" || { echo "FAIL new dir is not 700"; fail=1; }
mkdir -m 755 "$T/loose"
expect accepted "$T/loose" "an own dir with loose permissions"
[ "$(stat -c %a "$T/loose")" = 700 ] && echo "ok   own loose dir tightened to 700" || { echo "FAIL loose dir not tightened"; fail=1; }
exit $fail
