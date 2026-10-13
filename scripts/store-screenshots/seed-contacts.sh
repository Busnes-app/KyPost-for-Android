#!/usr/bin/env bash
# Adds the screenshot contacts to sam's relay address book. Idempotent: skips names already present.
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$WORK"
bash "$HERE/unlock-account.sh" >/dev/null
c() { curl -s --cacert tls/ca.pem -b jar -c jar "$@"; }
TOK=$(c "$R/api/auth/csrf" | sed -nE 's/.*"(csrfToken|token)":"([^"]*)".*/\2/p')
have=$(c "$R/api/contacts")

# given|family|email|org|title|phone
while IFS='|' read -r g f e o t p; do
  fn="$g $f"
  if printf '%s' "$have" | grep -qF "\"fn\":\"$fn\""; then echo "skip  $fn"; continue; fi
  printf '{"fn":"%s","givenName":"%s","familyName":"%s","org":"%s","title":"%s","emails":[{"label":"work","value":"%s"}],"phones":[{"label":"mobile","value":"%s"}]}' \
    "$fn" "$g" "$f" "$o" "$t" "$e" "$p" > contact.json
  code=$(c -o contact.out -w '%{http_code}' -H 'Content-Type: application/json' -H "X-CSRF-Token: $TOK" --data @contact.json "$R/api/contacts")
  echo "$code  $fn"; [ "${code:0:1}" = 2 ] || { head -c 300 contact.out; echo; exit 1; }
done <<'EOF'
Maya|Chen|maya.chen@example.com|Ridgeline Design|Product Designer|+1 555 0142
Jordan|Ellis|jordan@northwind.example|Northwind|Engineering Manager|+1 555 0177
Leo|Martins|leo@martins.example|||+1 555 0118
Priya|Raman|priya@raman.example|Lakeside Clinic|Pediatrician|+1 555 0163
Amara|Okafor|frontdesk@okaforclinic.example|Okafor Family Medicine|Physician|+1 555 0190
Dana|Whitfield|dana@whitfield.example|Elm Street Garden Club|Organizer|+1 555 0125
Ethan|Brooks|ethan.brooks@example.com|Harbor Credit Union|Advisor|+1 555 0134
Sofia|Alvarez|sofia@alvarez.example|Riverside Book Club||+1 555 0156
EOF
rm -f contact.json contact.out
