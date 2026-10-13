#!/usr/bin/env bash
# Gives some screenshot contacts a real (throwaway) OpenPGP public key. Idempotent.
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$WORK"
umask 077
export GNUPGHOME="$PWD/gnupg"
mkdir -p "$GNUPGHOME"
bash "$HERE/unlock-account.sh" >/dev/null
c() { curl -s --cacert tls/ca.pem -b jar -c jar "$@"; }
TOK=$(c "$R/api/auth/csrf" | sed -nE 's/.*"(csrfToken|token)":"([^"]*)".*/\2/p')
c "$R/api/contacts" > contacts.json

for who in "Maya Chen|maya.chen@example.com" "Jordan Ellis|jordan@northwind.example" "Priya Raman|priya@raman.example" "Leo Martins|leo@martins.example" "Amara Okafor|frontdesk@okaforclinic.example"; do
  fn=${who%%|*}; email=${who##*|}
  gpg -q --list-keys "$email" >/dev/null 2>&1 || gpg -q --batch --pinentry-mode loopback --passphrase '' --quick-gen-key "$fn <$email>" ed25519 cert,sign never
  gpg -q --list-keys "$email" | grep -q '\[E\]' || gpg -q --batch --pinentry-mode loopback --passphrase '' --quick-add-key "$(gpg --list-keys --with-colons "$email" | awk -F: '/^fpr/{print $10; exit}')" cv25519 encr never
  gpg -q --armor --export "$email" > key.asc
  python3 -I - "$fn" key.asc contacts.json contact.json <<'PY'
import json, sys
fn, keyfile, listfile, out = sys.argv[1:]
data = json.load(open(listfile))
items = data if isinstance(data, list) else next(v for v in data.values() if isinstance(v, list))
c = next(x for x in items if x.get("fn") == fn)
if c.get("pgpKey"):
    print("skip", fn); open(out, "w").write(""); sys.exit()
c["pgpKey"] = open(keyfile).read()
open(out, "w").write(json.dumps(c))
print("uid", c["uid"])
PY
  [ -s contact.json ] || continue
  uid=$(python3 -I -c 'import json;print(json.load(open("contact.json"))["uid"])')
  code=$(c -o put.out -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -H "X-CSRF-Token: $TOK" --data @contact.json "$R/api/contacts/$uid")
  echo "$code  $fn"; [ "${code:0:1}" = 2 ] || { head -c 300 put.out; echo; exit 1; }
done
rm -f contact.json put.out key.asc contacts.json
