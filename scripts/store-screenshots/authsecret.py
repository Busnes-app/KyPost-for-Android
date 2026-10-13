# Mirrors kypost-server users.DeriveAuthSecret:
# hex(HKDF-SHA256(PBKDF2-SHA256(pw, b64(salt), iters, 32), salt="", info="kypost/auth/v1", 32))
# Usage: python3 -I authsecret.py <password-file> <salt-b64> <iterations>
import base64, hashlib, hmac, sys

pw = open(sys.argv[1]).read().strip().encode()
stretch = hashlib.pbkdf2_hmac("sha256", pw, base64.b64decode(sys.argv[2]), int(sys.argv[3]), 32)
prk = hmac.new(b"\x00" * 32, stretch, hashlib.sha256).digest()
print(hmac.new(prk, b"kypost/auth/v1\x01", hashlib.sha256).hexdigest())
