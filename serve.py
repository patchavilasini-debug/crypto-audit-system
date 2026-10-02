# serve.py
# Production server.
#
# app.py uses Flask's built-in server, which handles one request at a
# time and prints a warning. This uses Waitress instead, which is built
# for real use.
#
#   set CRYPTO_AUDIT_ENV=production
#   set CRYPTO_AUDIT_SECRET=<a long random string>
#   python serve.py
#
# Behind a reverse proxy doing HTTPS, also set:
#   set CRYPTO_AUDIT_HTTPS=1

import os
import secrets

if os.environ.get("CRYPTO_AUDIT_ENV", "").lower() not in ("production", "prod"):
    os.environ["CRYPTO_AUDIT_ENV"] = "production"

if not os.environ.get("CRYPTO_AUDIT_SECRET"):
    print("")
    print("No secret key set. This signs the sign-in cookie, so it must not")
    print("be the built-in default on a server. Set one and start again:")
    print("")
    print("   set CRYPTO_AUDIT_SECRET=%s" % secrets.token_urlsafe(32))
    print("")
    raise SystemExit(1)

try:
    from waitress import serve
except ImportError:
    raise SystemExit("Waitress is not installed. Run: pip install waitress")

from app import app, database, auth

HOST = os.environ.get("CRYPTO_AUDIT_HOST", "0.0.0.0")
PORT = int(os.environ.get("CRYPTO_AUDIT_PORT", "8000"))

print("")
print("=" * 62)
print("CRYPTO AUDIT SYSTEM - production server (Waitress)")
print("=" * 62)
print("  Systems : %d" % database.count_systems())
print("  Accounts: %d" % auth.count_users())
print("  Listening on %s:%d" % (HOST, PORT))
print("  HTTPS cookie mode: %s"
      % ("on" if os.environ.get("CRYPTO_AUDIT_HTTPS") else "off - put a reverse proxy in front"))
print("  Stop with Ctrl+C")
print("=" * 62)
print("")

serve(app, host=HOST, port=PORT, threads=8, ident="Crypto Audit System")
