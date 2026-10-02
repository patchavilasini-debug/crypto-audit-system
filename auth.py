# auth.py
# Accounts, passwords and roles.
#
# Two roles:
#   auditor - can add, import, scan and delete
#   viewer  - can only look
#
# Passwords are never stored, only a salted hash. HOW they are hashed is
# not decided here: this file asks crypto_service, which follows the policy
# in crypto_policy.json. Change the policy and new passwords use the new
# algorithm; old ones keep working and are upgraded at the next sign in.
# This file never changes. That is crypto-agility.

import sqlite3
import os
import secrets
from functools import wraps

import crypto_service

# Slow down password guessing. After this many failures from the same
# account or the same address within the window, sign-in is refused for
# a while. The audit log records every attempt either way.
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

from flask import session, redirect, url_for, flash, request

import database

ROLES = ["auditor", "viewer"]


def init_users():
    conn = database.get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            salt     TEXT NOT NULL,
            hash     TEXT NOT NULL,
            role     TEXT NOT NULL DEFAULT 'viewer',
            created  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def hash_password(password):
    """The stored form. The service decides the algorithm."""
    return crypto_service.hash_password(password)


def add_user(username, password, role="viewer"):
    """Create an account. Returns (ok, message)."""
    username = str(username).strip()
    if not username:
        return False, "Username is required."
    if len(password) < 8:
        return False, "Password must be at least 8 characters."
    if role not in ROLES:
        return False, "Choose a valid role."

    init_users()
    salt, digest = "", hash_password(password)   # salt now lives inside the hash
    conn = database.get_connection()
    try:
        conn.execute(
            "INSERT INTO users (username, salt, hash, role, created) "
            "VALUES (?, ?, ?, ?, datetime('now'))",
            (username, salt, digest, role))
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        return False, "That username already exists."
    conn.close()
    return True, "Created " + username + "."


def init_attempts():
    conn = database.get_connection()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            address  TEXT,
            at       TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def recent_failures(username, address):
    """How many failed attempts in the last LOCKOUT_MINUTES, for this
       username or this address."""
    init_attempts()
    conn = database.get_connection()
    row = conn.execute(
        "SELECT COUNT(*) AS n FROM login_attempts "
        "WHERE at > datetime('now','localtime','-%d minutes') "
        "AND (username = ? OR address = ?)" % LOCKOUT_MINUTES,
        (str(username).strip(), str(address))).fetchone()
    conn.close()
    return row["n"]


def record_failure(username, address):
    init_attempts()
    conn = database.get_connection()
    conn.execute("INSERT INTO login_attempts (username, address, at) "
                 "VALUES (?, ?, datetime('now','localtime'))",
                 (str(username).strip(), str(address)))
    conn.commit()
    conn.close()


def clear_failures(username, address):
    init_attempts()
    conn = database.get_connection()
    conn.execute("DELETE FROM login_attempts WHERE username = ? OR address = ?",
                 (str(username).strip(), str(address)))
    conn.commit()
    conn.close()


def locked_out(username, address):
    """Returns minutes to wait, or 0 if sign-in is allowed."""
    if recent_failures(username, address) >= MAX_ATTEMPTS:
        return LOCKOUT_MINUTES
    return 0


def change_password(user_id, current, new, again):
    """Let someone change their own password. Returns (ok, message)."""
    if new != again:
        return False, "The two new passwords do not match."
    if len(new) < 8:
        return False, "The new password must be at least 8 characters."
    if new == current:
        return False, "The new password is the same as the old one."

    init_users()
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        conn.close()
        return False, "Account not found."
    if not crypto_service.verify_password(current, row["hash"], row["salt"]):
        conn.close()
        return False, "Your current password is not right."

    conn.execute("UPDATE users SET hash = ?, salt = '' WHERE id = ?",
                 (crypto_service.hash_password(new), user_id))
    conn.commit()
    conn.close()
    return True, "Password changed."


def check_password(username, password):
    """Return the user row if the password is right, else None."""
    init_users()
    conn = database.get_connection()
    row = conn.execute("SELECT * FROM users WHERE username = ?",
                       (str(username).strip(),)).fetchone()
    conn.close()
    if not row:
        # Still do the work, so a wrong username and a wrong password
        # take the same time. Otherwise the timing tells an attacker
        # which usernames exist.
        crypto_service.dummy_verify(password)
        return None

    if not crypto_service.verify_password(password, row["hash"], row["salt"]):
        return None

    # Right password. If it was hashed under an older policy, re-hash it now
    # under the current one. This is how a whole user base migrates to a new
    # algorithm without anyone being asked to reset their password.
    if crypto_service.needs_rehash(row["hash"]) or row["salt"]:
        conn = database.get_connection()
        conn.execute("UPDATE users SET hash = ?, salt = '' WHERE id = ?",
                     (crypto_service.hash_password(password), row["id"]))
        conn.commit()
        conn.close()
    return dict(row)


def password_algorithms():
    """How many accounts are on each algorithm - the migration progress."""
    init_users()
    conn = database.get_connection()
    rows = conn.execute("SELECT hash, salt FROM users").fetchall()
    conn.close()
    counts = {}
    for r in rows:
        name = crypto_service.password_algorithm(r["hash"], r["salt"])
        counts[name] = counts.get(name, 0) + 1
    return counts


def list_users():
    init_users()
    conn = database.get_connection()
    rows = conn.execute(
        "SELECT id, username, role, created FROM users ORDER BY id").fetchall()
    conn.close()
    return [dict(r) for r in rows]


def delete_user(user_id):
    conn = database.get_connection()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()


def count_users():
    init_users()
    conn = database.get_connection()
    n = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()
    return n


def seed_admin():
    """
    Create a first account so the site is usable on a fresh install.
    Returns the password so it can be shown once, then never again.
    """
    if count_users() > 0:
        return None
    password = "ChangeMe2026!"
    add_user("admin", password, "auditor")
    return password


# ---------------------------------------------------------------
# Route guards
# ---------------------------------------------------------------

def current_user():
    return session.get("user")


def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not current_user():
            flash("Sign in to continue.", "bad")
            return redirect(url_for("login", next=request.path))
        return fn(*args, **kwargs)
    return wrapper


def auditor_required(fn):
    """Viewers can look but not change anything."""
    @wraps(fn)
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user:
            flash("Sign in to continue.", "bad")
            return redirect(url_for("login", next=request.path))
        if user.get("role") != "auditor":
            flash("Your account can view the audit but not change it.", "bad")
            return redirect(url_for("inventory"))
        return fn(*args, **kwargs)
    return wrapper


if __name__ == "__main__":
    database.init_db()
    init_users()
    pw = seed_admin()
    print("Users in the database: %d" % count_users())
    if pw:
        print("Created the first account:")
        print("   username: admin")
        print("   password: " + pw)
        print("   Change it after the first sign in.")
    for u in list_users():
        print("   %-12s %-9s created %s" % (u["username"], u["role"], u["created"]))

    print("")
    print("Password check:")
    print("   right password ->", check_password("admin", "ChangeMe2026!") is not None)
    print("   wrong password ->", check_password("admin", "wrong") is not None)
    print("   no such user   ->", check_password("nobody", "anything") is not None)
