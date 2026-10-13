#!/usr/bin/env bash
# Reconciles sam's demo mailbox to the screenshot set (runs seed-mail.mjs inside the mail container).
set -euo pipefail
. "$(dirname "$0")/env.sh"
docker exec -i "$MAIL_CTR" node --input-type=module - < "$HERE/seed-mail.mjs"
