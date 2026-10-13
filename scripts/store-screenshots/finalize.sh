#!/usr/bin/env bash
# Writes six raw shots to a fastlane screenshot dir as opaque PNG24 and checks their size.
# Usage: finalize.sh <WxH> <dest-dir> <raw1> ... <raw6>   (raw names without .png)
set -euo pipefail
. "$(dirname "$0")/env.sh"
SIZE="$1"; DEST="$2"; shift 2
mkdir -p "$DEST"
i=1
for n in "$@"; do
  magick "$WORK/raw/$n.png" -alpha off -strip "PNG24:$DEST/$i.png"
  got=$(magick identify -format '%wx%h' "$DEST/$i.png")
  [ "$got" = "$SIZE" ] || { echo "$DEST/$i.png is $got, want $SIZE" >&2; exit 1; }
  i=$((i + 1))
done
file "$DEST"/*.png
