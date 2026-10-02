# database.py
# Stores systems in a SQLite file so they survive a restart.

import sqlite3
import os

DB_FILE = os.path.join("data", "crypto_audit.db")

FIELDS = ["name", "department", "type", "algorithm", "key_size",
          "sensitivity", "lifetime", "criticality",
          "secrecy_years", "migration_years", "exposure"]

# Columns added after the first version. Older databases get them added
# on start-up, with values worked out from what is already there.
NEW_SYSTEM_COLUMNS = [("secrecy_years", "REAL"), ("migration_years", "REAL"),
                      ("exposure", "TEXT")]
NEW_SCAN_COLUMNS = [("lifetime_days", "INTEGER"), ("not_before", "TEXT")]


def get_connection():
    if not os.path.exists("data"):
        os.makedirs("data")
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    init_scans()
    init_remediation()
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS systems (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT NOT NULL,
            department  TEXT NOT NULL DEFAULT 'Unassigned',
            type        TEXT NOT NULL,
            algorithm   TEXT NOT NULL,
            key_size    INTEGER NOT NULL,
            sensitivity TEXT NOT NULL,
            lifetime    TEXT NOT NULL,
            criticality TEXT NOT NULL,
            secrecy_years   REAL,
            migration_years REAL,
            exposure        TEXT
        )
    """)
    conn.commit()
    conn.close()
    upgrade_old_database()


def columns_of(conn, table):
    return [r["name"] for r in conn.execute("PRAGMA table_info(%s)" % table)]


def upgrade_old_database():
    """Bring a database made by an earlier version up to date, without
       losing anything already in it."""
    from risk_engine import fill_defaults
    conn = get_connection()

    have = columns_of(conn, "systems")
    for col, kind in NEW_SYSTEM_COLUMNS:
        if col not in have:
            conn.execute("ALTER TABLE systems ADD COLUMN %s %s" % (col, kind))

    have = columns_of(conn, "scans")
    for col, kind in NEW_SCAN_COLUMNS:
        if col not in have:
            conn.execute("ALTER TABLE scans ADD COLUMN %s %s" % (col, kind))
    conn.commit()

    rows = conn.execute("SELECT * FROM systems WHERE secrecy_years IS NULL "
                        "OR migration_years IS NULL OR exposure IS NULL").fetchall()
    for row in rows:
        filled = fill_defaults(dict(row))
        conn.execute("UPDATE systems SET secrecy_years = ?, migration_years = ?, "
                     "exposure = ?, lifetime = ? WHERE id = ?",
                     (filled["secrecy_years"], filled["migration_years"],
                      filled["exposure"], filled["lifetime"], row["id"]))
    conn.commit()
    conn.close()
    return len(rows)


# ---------------------------------------------------------------
# Scan results. Kept separately from the register, because a scan is
# a measurement with a date on it, not a permanent fact.
# ---------------------------------------------------------------

def init_scans():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            host        TEXT NOT NULL,
            scanned_at  TEXT NOT NULL,
            tls_version TEXT,
            algorithm   TEXT,
            key_size    INTEGER,
            issuer      TEXT,
            subject     TEXT,
            expires     TEXT,
            days_left   INTEGER,
            trusted     INTEGER,
            error       TEXT,
            lifetime_days INTEGER,
            not_before  TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_scan(r):
    """Record one scan. Every scan is kept, so a host builds a history."""
    init_scans()
    conn = get_connection()
    conn.execute(
        "INSERT INTO scans (host, scanned_at, tls_version, algorithm, key_size,"
        " issuer, subject, expires, days_left, trusted, error,"
        " lifetime_days, not_before)"
        " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
        (r.get("host"), r.get("scanned_at"), r.get("tls_version"),
         r.get("algorithm"), r.get("key_size"), r.get("issuer"),
         r.get("subject"), r.get("expires"), r.get("days_left"),
         1 if r.get("cert_trusted") else 0, r.get("error"),
         r.get("lifetime_days"), r.get("not_before")))
    conn.commit()
    conn.close()


def latest_scans():
    """The most recent scan for each host, newest first."""
    init_scans()
    conn = get_connection()
    rows = conn.execute("""
        SELECT * FROM scans
        WHERE id IN (SELECT MAX(id) FROM scans GROUP BY host)
        ORDER BY
          CASE WHEN error IS NOT NULL AND error != '' THEN 1 ELSE 0 END,
          days_left IS NULL,
          days_left ASC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def scan_history(host):
    """Every scan of one host, oldest first, so a change is visible."""
    init_scans()
    conn = get_connection()
    rows = conn.execute(
        "SELECT * FROM scans WHERE host = ? ORDER BY id", (host,)).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def scanned_hosts():
    init_scans()
    conn = get_connection()
    rows = conn.execute(
        "SELECT DISTINCT host FROM scans ORDER BY host").fetchall()
    conn.close()
    return [r["host"] for r in rows]


def count_scans():
    init_scans()
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    conn.close()
    return n


# ---------------------------------------------------------------
# Emergency steps taken on systems whose lock is already broken.
# ---------------------------------------------------------------

def init_remediation():
    conn = get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS remediation (
            system_id INTEGER NOT NULL,
            step      INTEGER NOT NULL,
            done_by   TEXT,
            done_at   TEXT,
            PRIMARY KEY (system_id, step)
        )
    """)
    conn.commit()
    conn.close()


def steps_done(system_id):
    """{step number: {"by": ..., "at": ...}} for one system."""
    init_remediation()
    conn = get_connection()
    rows = conn.execute("SELECT * FROM remediation WHERE system_id = ?",
                        (system_id,)).fetchall()
    conn.close()
    return {r["step"]: {"by": r["done_by"], "at": r["done_at"]} for r in rows}


def set_step(system_id, step, done, who):
    init_remediation()
    conn = get_connection()
    if done:
        conn.execute("INSERT OR REPLACE INTO remediation (system_id, step, done_by, done_at) "
                     "VALUES (?, ?, ?, datetime('now','localtime'))", (system_id, step, who))
    else:
        conn.execute("DELETE FROM remediation WHERE system_id = ? AND step = ?",
                     (system_id, step))
    conn.commit()
    conn.close()


def remediation_counts():
    """{system_id: number of steps done}, for the summary pages."""
    init_remediation()
    conn = get_connection()
    rows = conn.execute("SELECT system_id, COUNT(*) AS n FROM remediation "
                        "GROUP BY system_id").fetchall()
    conn.close()
    return {r["system_id"]: r["n"] for r in rows}


def add_system(system):
    """Save one system. Uses ? placeholders, which is what stops SQL injection."""
    from risk_engine import fill_defaults
    system = fill_defaults(system)
    conn = get_connection()
    values = [system[f] for f in FIELDS]
    placeholders = ",".join("?" * len(FIELDS))
    cur = conn.execute(
        "INSERT INTO systems (" + ",".join(FIELDS) + ") VALUES (" + placeholders + ")",
        values)
    conn.commit()
    new_id = cur.lastrowid
    conn.close()
    return new_id


def add_many(systems):
    for s in systems:
        add_system(s)


def get_all_systems():
    conn = get_connection()
    rows = conn.execute("SELECT * FROM systems ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_system(system_id):
    conn = get_connection()
    row = conn.execute("SELECT * FROM systems WHERE id = ?", (system_id,)).fetchone()
    conn.close()
    return dict(row) if row else None


def delete_system(system_id):
    init_remediation()
    conn = get_connection()
    conn.execute("DELETE FROM systems WHERE id = ?", (system_id,))
    conn.execute("DELETE FROM remediation WHERE system_id = ?", (system_id,))
    conn.commit()
    conn.close()


def count_systems():
    conn = get_connection()
    n = conn.execute("SELECT COUNT(*) FROM systems").fetchone()[0]
    conn.close()
    return n


def reset():
    if os.path.exists(DB_FILE):
        os.remove(DB_FILE)
    init_db()


def load_sample_data():
    """Fill an empty database with the sample systems. Does nothing if
       data already exists, so restarting does not duplicate rows."""
    from recommendation_engine import SAMPLE_SYSTEMS
    if count_systems() > 0:
        return 0
    add_many(SAMPLE_SYSTEMS)
    return len(SAMPLE_SYSTEMS)


if __name__ == "__main__":
    init_db()
    print("Database ready at " + DB_FILE)
    print("Sample systems added this run: " + str(load_sample_data()))
    systems = get_all_systems()
    print("Total systems stored: " + str(len(systems)))
    for s in systems:
        print("  %2d  %-28s %-16s %s-%s"
              % (s["id"], s["name"], s["department"], s["algorithm"], s["key_size"]))
