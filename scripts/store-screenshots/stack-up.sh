#!/usr/bin/env bash
# Throwaway TLS CA + relay + demo IMAP stack. Re-runnable: keeps existing keys/passwords.
set -euo pipefail
. "$(dirname "$0")/env.sh"
cd "$WORK"; umask 077; mkdir -p tls

if [ ! -f tls/server.pem ]; then
  ( cd tls
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 7 -subj "/CN=KyPost Screenshot Throwaway CA" \
      -keyout ca.key -out ca.pem -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign" 2>/dev/null
    openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=10.0.2.2" -keyout server.key -out server.csr 2>/dev/null
    printf 'subjectAltName=IP:10.0.2.2,IP:127.0.0.1\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\n' > ext.cnf
    openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -days 7 -extfile ext.cnf -out server.pem 2>/dev/null
    chmod 644 server.key server.pem ca.pem )   # read by the relay's non-root user
fi
test -f admin.pass || openssl rand -base64 18 | tr -d '/+=' > admin.pass
printf 'BOOTSTRAP_ADMIN_PASS=%s\n' "$(cat admin.pass)" > relay.env

cat > compose.yml <<EOF
# Throwaway local stack for store screenshots. Relay is published on host loopback only.
name: $PROJECT
networks:
  shots:
    ipam:
      config: [{ subnet: $NET.0/24 }]
volumes: { mail_tls: {}, cfg: {}, priv: {}, logs: {}, state: {} }
services:
  mail:
    image: kypost-demo-mail:local
    mem_limit: 256m
    memswap_limit: 256m
    networks: { shots: { ipv4_address: $NET.20 } }
    environment:
      ALLOWED_CLIENT_IPS: "$NET.10,127.0.0.1,::1"
      TLS_HOSTNAMES: "mail,localhost"
      TLS_IPS: "$NET.20,127.0.0.1"
      DRIP_SECONDS: "86400"
    volumes: [ "mail_tls:/srv/tls-public" ]
    tmpfs: [ "/run/kypost-tls:mode=0700,uid=10001,gid=10001" ]
    read_only: true
    cap_drop: [ALL]
    security_opt: [ "no-new-privileges:true" ]
  relay:
    image: ghcr.io/busnes-app/kypost-server:main
    mem_limit: 3g
    memswap_limit: 3g
    depends_on: { mail: { condition: service_healthy } }
    networks: { shots: { ipv4_address: $NET.10 } }
    ports: [ "127.0.0.1:$PORT:5866" ]
    environment:
      WEB_PORT: 5866
      KYPOST_BIND: 0.0.0.0
      SERVER_BASE_URL: https://10.0.2.2:$PORT
      TLS_CERT_FILE: /srv/relay-tls/server.pem
      TLS_KEY_FILE: /srv/relay-tls/server.key
      SSL_CERT_DIR: "/etc/ssl/certs:/srv/kypost-demo-tls"
      SANDBOX_PRIVATE_HOSTS: mail
      IMAP_HOST: mail
      IMAP_PORT: "993"
      IMAP_USERNAME: sam@kypost-demo.local
      IMAP_PASSWORD: demo
      SMTP_HOST: mail
      SMTP_PORT: "587"
      BOOTSTRAP_ADMIN_USER: sam
      REVIEW_PAIRING_USERNAME: sam
      CAPTCHA_PROVIDER: none
      OLLAMA_BASE_URL: http://127.0.0.1:9
      TZ: America/New_York
    env_file: [ relay.env ]
    volumes:
      - mail_tls:/srv/kypost-demo-tls:ro
      - ./tls/server.pem:/srv/relay-tls/server.pem:ro
      - ./tls/server.key:/srv/relay-tls/server.key:ro
      - cfg:/kypost/config
      - priv:/kypost/private
      - logs:/kypost/logs
      - state:/kypost/state
EOF

docker compose -f compose.yml up -d > compose.log 2>&1 || { tail -20 compose.log; exit 1; }
for _ in $(seq 1 60); do
  docker compose -f compose.yml ps relay --format '{{.Status}}' | grep -q '(healthy)' && break
  sleep 3
done
docker compose -f compose.yml ps --format '{{.Service}}\t{{.Status}}'
