#!/usr/bin/env bash
# Trusts the throwaway CA system-wide on a rooted (google_apis) emulator until its next reboot.
# Re-runnable. Force-stops the app so it picks up the new trust store.
set -euo pipefail
. "$(dirname "$0")/env.sh"
H=$(openssl x509 -in "$WORK/tls/ca.pem" -subject_hash_old -noout)
adb root >/dev/null; adb wait-for-device
adb push "$WORK/tls/ca.pem" "/data/local/tmp/$H.0" >/dev/null
adb shell sh -s "$H" <<'EOF'
set -e
H="$1"
if ls "/apex/com.android.conscrypt/cacerts/$H.0" >/dev/null 2>&1; then echo "CA already trusted"; exit 0; fi
mkdir -p /data/local/tmp/cacerts
cp /apex/com.android.conscrypt/cacerts/* /data/local/tmp/cacerts/
cp "/data/local/tmp/$H.0" /data/local/tmp/cacerts/
mount -t tmpfs tmpfs /system/etc/security/cacerts
cp /data/local/tmp/cacerts/* /system/etc/security/cacerts/
chown root:root /system/etc/security/cacerts/*
chmod 644 /system/etc/security/cacerts/*
chcon u:object_r:system_file:s0 /system/etc/security/cacerts/*
for Z in $(pidof zygote zygote64); do
  nsenter --mount=/proc/$Z/ns/mnt -- mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
done
mount --bind /system/etc/security/cacerts /apex/com.android.conscrypt/cacerts
ls "/apex/com.android.conscrypt/cacerts/$H.0"
EOF
adb shell am force-stop org.kysecurity.mail
