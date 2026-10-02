# notifier.py
# Emails people before a certificate expires.
#
# Two modes:
#   OUTBOX  - the default. Emails are written as files into the outbox
#             folder instead of being sent. Works with no setup, so the
#             feature can be shown without a mail account.
#   SMTP    - real sending. Set these environment variables first:
#               CRYPTO_AUDIT_SMTP_HOST   e.g. smtp.gmail.com
#               CRYPTO_AUDIT_SMTP_PORT   e.g. 587
#               CRYPTO_AUDIT_SMTP_USER   your email address
#               CRYPTO_AUDIT_SMTP_PASS   an app password, not your normal one
#
# Run the check on its own:   python notifier.py
# Run it every day with Windows Task Scheduler - see ALERTS.md

import os
import re
import smtplib
import datetime
from email.message import EmailMessage

import database
import scanner

OUTBOX = "outbox"
THRESHOLDS = [7, 14, 30, 60, 90]

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


# ---------------------------------------------------------------
# Storage
# ---------------------------------------------------------------

def init_alerts():
    conn = database.get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host        TEXT NOT NULL,
            email       TEXT NOT NULL,
            days_before INTEGER NOT NULL,
            created     TEXT NOT NULL,
            created_by  TEXT,
            last_sent   TEXT,
            last_days   INTEGER,
            UNIQUE(host, email)
        )
    """)
    conn.commit()
    conn.close()


def valid_email(email):
    return bool(EMAIL_PATTERN.match(str(email).strip()))


def add_alert(host, email, days_before, created_by=""):
    """Subscribe an address to a host. Returns (ok, message)."""
    host = scanner.clean_host(host)
    email = str(email).strip().lower()

    if not host:
        return False, "No host given."
    if not valid_email(email):
        return False, "That does not look like an email address."
    try:
        days_before = int(days_before)
    except (TypeError, ValueError):
        return False, "Choose how many days warning you want."
    if days_before not in THRESHOLDS:
        return False, "Choose how many days warning you want."

    init_alerts()
    conn = database.get_connection()
    # One subscription per address per host. Asking again updates the
    # warning period rather than creating a duplicate that emails twice.
    existing = conn.execute("SELECT id FROM alerts WHERE host = ? AND email = ?",
                            (host, email)).fetchone()
    if existing:
        conn.execute("UPDATE alerts SET days_before = ?, last_sent = NULL, "
                     "last_days = NULL WHERE id = ?", (days_before, existing["id"]))
        message = "Updated: %s will be emailed %d days before %s expires." % (
            email, days_before, host)
    else:
        conn.execute(
            "INSERT INTO alerts (host, email, days_before, created, created_by) "
            "VALUES (?, ?, ?, datetime('now','localtime'), ?)",
            (host, email, days_before, created_by))
        message = "Done: %s will be emailed %d days before %s expires." % (
            email, days_before, host)
    conn.commit()
    conn.close()
    return True, message


def list_alerts():
    init_alerts()
    conn = database.get_connection()
    rows = conn.execute("SELECT * FROM alerts ORDER BY host, email").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_alert(alert_id):
    init_alerts()
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM alerts WHERE id = ?", (alert_id,)).fetchone()
    conn.execute("DELETE FROM alerts WHERE id = ?", (alert_id,))
    conn.commit()
    conn.close()
    return dict(row) if row else None


def mark_sent(alert_id, days_left):
    conn = database.get_connection()
    conn.execute("UPDATE alerts SET last_sent = datetime('now','localtime'), "
                 "last_days = ? WHERE id = ?", (days_left, alert_id))
    conn.commit()
    conn.close()


# ---------------------------------------------------------------
# Sending
# ---------------------------------------------------------------

def smtp_settings():
    host = os.environ.get("CRYPTO_AUDIT_SMTP_HOST")
    user = os.environ.get("CRYPTO_AUDIT_SMTP_USER")
    password = os.environ.get("CRYPTO_AUDIT_SMTP_PASS")
    if not (host and user and password):
        return None
    return {"host": host,
            "port": int(os.environ.get("CRYPTO_AUDIT_SMTP_PORT", "587")),
            "user": user, "password": password}


def mode():
    return "smtp" if smtp_settings() else "outbox"


def build_message(alert, scan):
    days = scan.get("days_left")
    host = alert["host"]
    if scan.get("error"):
        subject = "Could not check the certificate for %s" % host
    elif days is None:
        subject = "Could not read the expiry date for %s" % host
    elif days < 0:
        subject = "EXPIRED: the certificate for %s has expired" % host
    elif days <= 7:
        subject = "URGENT: %s certificate expires in %d days" % (host, days)
    else:
        subject = "%s certificate expires in %d days" % (host, days)

    lines = ["The certificate for %s needs attention." % host, ""]
    if scan.get("error"):
        lines += ["We tried to check it and could not reach the server:",
                  "   " + scan["error"], ""]
    else:
        lines += [
            "   Expires      : %s" % scan.get("expires", "unknown"),
            "   Days left    : %s" % days,
            "   Issued by    : %s" % scan.get("issuer", "unknown"),
            "   Certificate  : %s-%s" % (scan.get("algorithm", "?"),
                                          scan.get("key_size", "?")),
            "   TLS version  : %s" % scan.get("tls_version", "unknown"),
            "",
        ]

    lines += [
        "What happens if it expires:",
        "   Browsers show a full page warning and most visitors turn back.",
        "   Apps and other systems refuse to connect at all.",
        "   The server keeps running, but in practice the service is down.",
        "",
        "What to do:",
        "   Renew the certificate with whoever issued it.",
        "   If you can, switch to automatic renewal with 90 day certificates,",
        "   so this does not depend on somebody remembering.",
        "",
        "You asked to be told %d days before expiry." % alert["days_before"],
        "",
        "-- Crypto Audit System",
    ]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["To"] = alert["email"]
    settings = smtp_settings()
    msg["From"] = settings["user"] if settings else "crypto-audit@localhost"
    msg.set_content("\n".join(lines))
    return msg


def deliver(msg):
    """Send it, or file it in the outbox. Returns (ok, where)."""
    settings = smtp_settings()

    if not settings:
        if not os.path.exists(OUTBOX):
            os.makedirs(OUTBOX)
        stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S-%f")
        safe = re.sub(r"[^a-z0-9]+", "-", msg["To"].lower())[:40]
        path = os.path.join(OUTBOX, "%s_%s.eml" % (stamp, safe))
        with open(path, "w", encoding="utf-8") as f:
            f.write(msg.as_string())
        return True, path

    try:
        with smtplib.SMTP(settings["host"], settings["port"], timeout=20) as s:
            s.starttls()
            s.login(settings["user"], settings["password"])
            s.send_message(msg)
        return True, "sent to " + msg["To"]
    except smtplib.SMTPAuthenticationError:
        return False, ("The mail server refused the login. For Gmail you need "
                       "an app password, not your normal password.")
    except Exception as e:
        return False, "Could not send: %s" % str(e)[:120]


def send_test(email):
    """A single test message, so someone can confirm delivery works."""
    if not valid_email(email):
        return False, "That does not look like an email address."
    msg = EmailMessage()
    msg["Subject"] = "Test from the Crypto Audit System"
    msg["To"] = email.strip()
    settings = smtp_settings()
    msg["From"] = settings["user"] if settings else "crypto-audit@localhost"
    msg.set_content("If you can read this, certificate expiry alerts will "
                    "reach this address.\n\n-- Crypto Audit System")
    return deliver(msg)


# ---------------------------------------------------------------
# The check
# ---------------------------------------------------------------

def check_all(rescan=True, force=False):
    """
    Look at every subscription and email anyone whose host is inside
    their warning period.

    An email goes out when the host crosses the threshold, and again if
    it gets at least a week closer, but not every single day - otherwise a
    30 day warning would send thirty emails.
    """
    init_alerts()
    alerts = list_alerts()
    report = []
    scans = {}

    for alert in alerts:
        host = alert["host"]

        if host not in scans:
            if rescan:
                r = scanner.scan_host(host)
                database.save_scan(r)
            else:
                history = database.scan_history(host)
                r = history[-1] if history else {"host": host,
                                                  "error": "Never scanned."}
            scans[host] = r

        scan = scans[host]
        days = scan.get("days_left")

        if scan.get("error"):
            due = True
            reason = "server unreachable"
        elif days is None:
            due = False
            reason = "expiry unknown"
        elif days > alert["days_before"]:
            due = False
            reason = "%d days left, warning set at %d" % (days, alert["days_before"])
        else:
            due = True
            reason = "%d days left, inside the %d day warning" % (days, alert["days_before"])

        # Do not repeat unless it has got at least a week closer.
        if (due and not force and alert.get("last_days") is not None
                and days is not None and days >= 0):
            if alert["last_days"] - days < 7:
                due = False
                reason = "already warned at %d days" % alert["last_days"]

        entry = {"alert": alert, "days": days, "due": due, "reason": reason,
                 "sent": False, "where": ""}

        if due:
            ok, where = deliver(build_message(alert, scan))
            entry["sent"] = ok
            entry["where"] = where
            if ok:
                mark_sent(alert["id"], days if days is not None else -1)

        report.append(entry)

    return report


if __name__ == "__main__":
    database.init_db()
    init_alerts()

    print("=" * 62)
    print("CERTIFICATE EXPIRY CHECK")
    print("Mode: %s" % ("sending real email" if mode() == "smtp"
                        else "outbox - emails saved to the outbox folder"))
    print("=" * 62)

    alerts = list_alerts()
    if not alerts:
        print("")
        print("Nobody has asked for alerts yet.")
        print("Scan a host on the website and use 'Email me before this expires'.")
        raise SystemExit(0)

    for e in check_all():
        a = e["alert"]
        mark = "SENT " if e["sent"] else ("FAIL " if e["due"] else "     ")
        print("  %s %-24s %-28s %s" % (mark, a["host"][:24], a["email"][:28], e["reason"]))
        if e["where"]:
            print("        -> " + e["where"])
