# Deploying this

Two ways. Pick the one that matches who will use it.

---

## A. One office, one machine  (simplest)

Good for a demo, a review, or one department using it internally.

```
setup.bat          once
run-network.bat    every time
```

The window prints the address other machines on the same network should
open. If they cannot reach it, Windows Firewall is blocking the port -
`SETUP.md` has the one-line command to allow it.

Your machine has to stay switched on.

---

## B. A proper server

### 1. Make a secret key

This signs the sign-in cookie. Without a real one, anybody who has seen
this code could forge a session, so the site refuses to start in
production mode with the default.

```
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Copy what it prints.

### 2. Start it with Waitress

Flask's built-in server handles one request at a time. Waitress is built
for real use and is installed by `setup.bat`.

```
set CRYPTO_AUDIT_ENV=production
set CRYPTO_AUDIT_SECRET=<the key from step 1>
set CRYPTO_AUDIT_PORT=8000
python serve.py
```

### 3. Put HTTPS in front

Never run a government register over plain HTTP. Either:

- a reverse proxy (IIS, nginx or Apache) holding the certificate and
  passing requests to port 8000, which is the usual arrangement; or
- the built-in HTTPS for a small deployment:
  `python make_cert.py` then `python app.py --https`

When HTTPS is in front, also set:

```
set CRYPTO_AUDIT_HTTPS=1
```

so the sign-in cookie is only ever sent over HTTPS.

### 4. Back it up

```
python backup.py
```

Everything lives in one SQLite file, so one copy is a full backup -
systems, accounts, audit log, scans, alerts. Schedule it daily with
Windows Task Scheduler, the same way as `run-alerts.bat`. It keeps the
last 30 copies.

To restore: stop the site, copy a backup over `data\crypto_audit.db`,
start it again.

### 5. First sign in

```
username: admin
password: ChangeMe2026!
```

Create your own account under **Accounts**, sign in as that, then delete
`admin`. Change your password from the **Password** link in the header.

---

## What is already hardened

- Every form carries a one-time token, so another site cannot make your
  browser change anything here
- Deleting and re-scanning are POST-only, never a plain link
- Five failed sign-ins lock the account or address for 15 minutes
- Passwords are stored as a salted PBKDF2 hash, never in plain text
- The sign-in cookie is script-proof, same-site, and HTTPS-only in
  production
- Security headers: no framing, no sniffing, no referrer leakage, and a
  content security policy
- Uploads are capped at 25 MB
- Every change is written to an append-only audit log

## What is not done

- **A CERT-In empanelled audit.** Government web applications in India
  normally need one before going live. Everything above is what an
  auditor checks first, but the audit itself is theirs to run.
- **SQLite, not PostgreSQL.** Fine for one department. For hundreds of
  people writing at once, move the database.
- **No single sign-on.** Accounts are local to this site.

---

## Where to run it

Inside the organisation's own network, not on the public internet. The
register lists which systems have weak cryptography, which is exactly
what an attacker would want. Reachable from department desks, blocked at
the perimeter.
