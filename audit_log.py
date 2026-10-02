# audit_log.py
# Who changed what, and when.
#
# The problem statement asks for an auditable system. An audit tool that
# cannot itself be audited is a gap, so every change is recorded and the
# log is append only - there is no function here that deletes a row.

import database

ACTIONS = {
    "login":       "Signed in",
    "login_fail":  "Failed sign in",
    "logout":      "Signed out",
    "add":         "Added a system",
    "delete":      "Removed a system",
    "import":      "Imported from CSV",
    "scan":        "Scanned a host",
    "scan_save":   "Saved a scan result",
    "user_add":    "Created an account",
    "user_delete": "Removed an account",
    "export":      "Exported the audit",
    "alert_add":    "Asked for expiry emails",
    "alert_delete": "Stopped expiry emails",
    "alert_check":  "Ran the expiry email check",
    "alert_test":   "Sent a test email",
    "policy_change": "Changed the crypto policy",
    "remediate":     "Emergency step",
    "seal":          "Re-sealed a document",
    "code_scan":     "Scanned source code",
    "csrf_blocked":  "Blocked a forged request",
    "lockout":       "Sign-in locked out",
    "password_change": "Changed own password",
}


def init_log():
    conn = database.get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id      INTEGER PRIMARY KEY AUTOINCREMENT,
            at      TEXT NOT NULL,
            who     TEXT NOT NULL,
            action  TEXT NOT NULL,
            detail  TEXT,
            address TEXT
        )
    """)
    conn.commit()
    conn.close()


def record(who, action, detail="", address=""):
    """Write one line. Never fails loudly - a logging problem must not
       stop somebody doing their job."""
    try:
        init_log()
        conn = database.get_connection()
        conn.execute(
            "INSERT INTO audit_log (at, who, action, detail, address) "
            "VALUES (datetime('now','localtime'), ?, ?, ?, ?)",
            (str(who), str(action), str(detail)[:300], str(address)[:45]))
        conn.commit()
        conn.close()
    except Exception:
        pass


def recent(limit=200, action=None, who=None):
    init_log()
    conn = database.get_connection()
    sql = "SELECT * FROM audit_log"
    where, params = [], []
    if action:
        where.append("action = ?")
        params.append(action)
    if who:
        where.append("who = ?")
        params.append(who)
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY id DESC LIMIT ?"
    params.append(int(limit))
    rows = conn.execute(sql, params).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def summary():
    init_log()
    conn = database.get_connection()
    total = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
    fails = conn.execute(
        "SELECT COUNT(*) FROM audit_log WHERE action = 'login_fail'").fetchone()[0]
    people = conn.execute(
        "SELECT COUNT(DISTINCT who) FROM audit_log").fetchone()[0]
    last = conn.execute(
        "SELECT at FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
    conn.close()
    return {"total": total, "failed_logins": fails, "people": people,
            "last": last[0] if last else "never"}


def label(action):
    return ACTIONS.get(action, action)


if __name__ == "__main__":
    database.init_db()
    init_log()
    record("admin", "login", "", "127.0.0.1")
    record("admin", "add", "Added Water Billing (Municipal Admin)", "127.0.0.1")
    record("priya", "login_fail", "wrong password", "192.168.1.22")
    record("admin", "scan", "apgov.in -> RSA-2048", "127.0.0.1")
    record("admin", "delete", "Removed Legacy Booking Archive", "127.0.0.1")

    s = summary()
    print("Entries: %d   People: %d   Failed logins: %d   Last: %s"
          % (s["total"], s["people"], s["failed_logins"], s["last"]))
    print("")
    print("%-20s %-10s %-22s %s" % ("WHEN", "WHO", "WHAT", "DETAIL"))
    print("-" * 78)
    for r in recent(10):
        print("%-20s %-10s %-22s %s"
              % (r["at"], r["who"], label(r["action"]), (r["detail"] or "")[:30]))
