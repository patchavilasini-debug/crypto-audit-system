# backup.py
# Copies the database to a dated file in the backups folder.
#
#   python backup.py
#
# Everything lives in one SQLite file, so one copy is a full backup:
# systems, accounts, the audit log, scans, alerts and emergency steps.
# Schedule it daily with Windows Task Scheduler, the same way as the
# expiry check.

import datetime
import os
import shutil
import sqlite3

import database

BACKUP_DIR = "backups"
KEEP = 30          # how many daily copies to keep


def backup():
    if not os.path.exists(database.DB_FILE):
        print("No database yet - nothing to back up.")
        return None

    if not os.path.exists(BACKUP_DIR):
        os.makedirs(BACKUP_DIR)

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    target = os.path.join(BACKUP_DIR, "crypto_audit-%s.db" % stamp)
    n = 2
    while os.path.exists(target):          # never overwrite an earlier copy
        target = os.path.join(BACKUP_DIR, "crypto_audit-%s-%d.db" % (stamp, n))
        n += 1

    # Use SQLite's own backup, so a copy taken while people are using
    # the site is still a valid database.
    source = sqlite3.connect(database.DB_FILE)
    dest = sqlite3.connect(target)
    with dest:
        source.backup(dest)
    dest.close()
    source.close()
    return target


def tidy():
    files = sorted(f for f in os.listdir(BACKUP_DIR) if f.endswith(".db"))
    removed = 0
    while len(files) > KEEP:
        os.remove(os.path.join(BACKUP_DIR, files.pop(0)))
        removed += 1
    return removed


if __name__ == "__main__":
    path = backup()
    if path:
        size = os.path.getsize(path) / 1024.0
        print("Backed up to %s (%.0f KB)" % (path, size))
        n = tidy()
        if n:
            print("Removed %d old backup(s), keeping the most recent %d." % (n, KEEP))
        print("")
        print("To restore: stop the site, copy a backup over")
        print("   %s" % database.DB_FILE)
        print("and start it again.")
