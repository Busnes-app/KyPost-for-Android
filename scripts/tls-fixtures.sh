#!/usr/bin/env bash
# Regenerates the public, test-only TLS fixtures StrongTlsDeviceTest serves on loopback.
# Keys are throwaway and committed on purpose; nothing trusts them outside that test.
set -euo pipefail
out="$(cd "$(dirname "$0")/.." && pwd)/app/src/androidTest/resources/tls"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"
days=36500

key() { # name algorithm-args...
  local name="$1"; shift
  openssl genpkey -quiet "$@" -out "$name.pem"
  openssl pkcs8 -topk8 -nocrypt -in "$name.pem" -outform DER -out "$out/$name.key.der"
}
root() { # name
  openssl req -x509 -new -key "$1.pem" -sha256 -days "$days" -subj "/CN=KyPost TLS fixture $1" \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign,cRLSign -out "$1.crt"
}
issue() { # name issuer is-ca [digest]
  local ext="$work/$1.ext"
  if [ "$3" = ca ]; then
    printf 'basicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\n' >"$ext"
  else
    printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n' >"$ext"
  fi
  openssl req -new -key "$1.pem" -subj "/CN=KyPost TLS fixture $1" -out "$1.csr"
  openssl x509 -req -in "$1.csr" -CA "$2.crt" -CAkey "$2.pem" -CAcreateserial "-${4:-sha256}" -days "$days" \
    -extfile "$ext" -out "$1.crt"
}

rsa() { key "$1" -algorithm RSA -pkeyopt "rsa_keygen_bits:$2"; }
rsa root_rsa2048 2048; root root_rsa2048
rsa root_rsa2047 2047; root root_rsa2047
rsa intermediate_rsa2047 2047; issue intermediate_rsa2047 root_rsa2048 ca
rsa leaf_rsa2048 2048; issue leaf_rsa2048 root_rsa2048 leaf
key leaf_p256 -algorithm EC -pkeyopt ec_paramgen_curve:P-256; issue leaf_p256 root_rsa2048 leaf
rsa leaf_rsa1024 1024; issue leaf_rsa1024 root_rsa2048 leaf
rsa leaf_under_weak_root 2048; issue leaf_under_weak_root root_rsa2047 leaf
rsa leaf_under_weak_intermediate 2048; issue leaf_under_weak_intermediate intermediate_rsa2047 leaf
rsa leaf_sha1 2048; issue leaf_sha1 root_rsa2048 leaf sha1

for c in *.crt; do cp "$c" "$out/$c"; done
rm -f "$out"/root_*.key.der "$out"/intermediate_*.key.der  # only served leaves need keys
# StrongTlsTest checks the same certificates on the JVM; it needs no keys.
jvm="$(dirname "$out")/../../test/resources/tls"
mkdir -p "$jvm"
cp "$out"/*.crt "$jvm/"
