#!/usr/bin/env bash
# Readies "sam" for review pairing: clears the bootstrap forced password change and points
# the account at the demo mailbox. Re-runnable; makes at most one failed login per run.
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$WORK"
umask 077
ITERS=600000
c() { curl -s --cacert tls/ca.pem -b jar -c jar "$@"; }
secret() { printf '%s' "$1" > pw.tmp; python3 -I "$HERE/authsecret.py" pw.tmp "$2" "$3"; rm -f pw.tmp; }

# Sends both credential forms; the server checks whichever the account stores (and may
# upgrade a legacy account to derived auth with these params).
params() {
  local p
  p=$(c "$R/api/auth/login-params?username=sam")
  SALT=$(printf '%s' "$p" | sed -nE 's/.*"salt":"([^"]*)".*/\1/p')
  LITERS=$(printf '%s' "$p" | sed -nE 's/.*"iterations":([0-9]+).*/\1/p')
}
# Call params first: login runs in a $(...) subshell.
login() {
  printf '{"username":"sam","password":"%s","authSecret":"%s","loginSalt":"%s","loginIterations":%s}' \
    "$1" "$(secret "$1" "$SALT" "$LITERS")" "$SALT" "$LITERS" > req.json
  c -o login.out -w '%{http_code}' -H 'Content-Type: application/json' --data @req.json "$R/api/auth/login"
  rm -f req.json
}
csrf() { c "$R/api/auth/csrf" | sed -nE 's/.*"(csrfToken|token)":"([^"]*)".*/\2/p'; }

test -f admin.pass.new || openssl rand -base64 18 | tr -d '/+=' > admin.pass.new
NEW=$(cat admin.pass.new)
rm -f jar

if [ -f .rotated ]; then
  params; code=$(login "$NEW"); echo "login (rotated): $code"; [ "$code" = 200 ] || { head -c 300 login.out; echo; exit 1; }
else
  OLD=$(cat admin.pass)
  params; code=$(login "$OLD"); echo "login (bootstrap): $code"; [ "$code" = 200 ] || { head -c 300 login.out; echo; exit 1; }
  NSALT=$(openssl rand -base64 16)
  printf '{"oldPassword":"%s","oldAuthSecret":"%s","newPassword":"%s","newAuthSecret":"%s","newLoginSalt":"%s","newIterations":%s}' \
    "$OLD" "$(secret "$OLD" "$SALT" "$LITERS")" "$NEW" "$(secret "$NEW" "$NSALT" "$ITERS")" "$NSALT" "$ITERS" > req.json
  code=$(c -o pw.out -w '%{http_code}' -H 'Content-Type: application/json' -H "X-CSRF-Token: $(csrf)" --data @req.json "$R/api/auth/password")
  rm -f req.json
  echo "change password: $code"; [ "$code" = 200 ] || { head -c 300 pw.out; echo; exit 1; }
  touch .rotated
fi
c "$R/api/auth/me" | grep -oE '"(username|mustChangePassword)":[^,}]*' || true

# POST overwrites, so re-running is safe.
printf '%s' '{"host":"mail","port":993,"username":"sam@kypost-demo.local","password":"demo","mailbox":"INBOX","smtpHost":"mail","smtpPort":587}' > req.json
code=$(c -o imap.out -w '%{http_code}' -H 'Content-Type: application/json' -H "X-CSRF-Token: $(csrf)" --data @req.json "$R/api/imap/config")
rm -f req.json
echo "imap config: $code"; [ "$code" = 200 ] || { head -c 300 imap.out; echo; exit 1; }

# A fresh account can start with an empty allowlist, which buckets everything as Uncategorized.
printf '%s' '{"autoApplyEnabled":true,"allowlist":["Primary","Promotions","Social","Updates"],"keywordMappings":{},"descriptions":{}}' > req.json
code=$(c -o labels.out -w '%{http_code}' -X PUT -H 'Content-Type: application/json' -H "X-CSRF-Token: $(csrf)" --data @req.json "$R/api/labels/preferences")
rm -f req.json
echo "label allowlist: $code"; [ "$code" = 200 ] || { head -c 300 labels.out; echo; exit 1; }
