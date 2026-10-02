# app.py
# The web server. Contains no maths - every number comes from the engines.

import os
import secrets
from datetime import date

from flask import (Flask, render_template, request, redirect, url_for,
                   flash, Response, session)

import database
from crypto_rules import CRYPTO_RULES
from risk_engine import (SENSITIVITY_SCALE, CRITICALITY_SCALE, EXPOSURE_SCALE,
                         WEIGHTS, QUANTUM_HORIZON, GAP_CAP, calculate_risk)
from recommendation_engine import (audit_all, summarise, build_plan,
                                   by_department, departments, scenario_table,
                                   MIGRATION_STEPS)
import cbom
import code_scan
import crypto_service
import csv_import
import advisory
import scanner
import auth
import audit_log
import notifier
from auth import login_required, auditor_required, current_user

app = Flask(__name__)
# In production read this from an environment variable so it is not in
# the source. A fixed key here means sessions survive a restart, which is
# what we want for a demo.
# ---------------------------------------------------------------
# Secret key.
#
# This signs the sign-in cookie. If it is the built-in default, anybody
# who has seen this code could forge a session. That is fine on a laptop
# and unacceptable on a server, so production mode refuses to start
# without a real one.
# ---------------------------------------------------------------
DEFAULT_SECRET = "change-this-in-production"
PRODUCTION = os.environ.get("CRYPTO_AUDIT_ENV", "").lower() in ("production", "prod")

app.secret_key = os.environ.get("CRYPTO_AUDIT_SECRET", DEFAULT_SECRET)

if PRODUCTION and app.secret_key == DEFAULT_SECRET:
    raise SystemExit(
        "\nRefusing to start in production without a secret key.\n"
        "Set one first, for example:\n"
        "   set CRYPTO_AUDIT_SECRET=%s\n"
        % secrets.token_urlsafe(32))

# The sign-in cookie: not readable by scripts, not sent to other sites,
# and HTTPS-only when the site is served over HTTPS.
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("CRYPTO_AUDIT_HTTPS", "").lower() in ("1", "true", "yes"),
    MAX_CONTENT_LENGTH=25 * 1024 * 1024,      # the largest upload accepted
)


@app.after_request
def security_headers(response):
    """Standard protections an auditor looks for."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; form-action 'self'")
    if PRODUCTION:
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response


@app.errorhandler(413)
def too_big(_):
    flash("That file is too large. The limit is 25 MB.", "bad")
    return redirect(request.referrer or url_for("dashboard")), 413

database.init_db()
database.load_sample_data()
auth.init_users()
audit_log.init_log()
notifier.init_alerts()
FIRST_PASSWORD = auth.seed_admin()


# ---------------------------------------------------------------
# Cross-site request forgery protection.
#
# Without this, another website could quietly make your browser send a
# request here - deleting a system, changing the crypto policy - just by
# getting you to visit a page while signed in. Every form carries a
# secret token that only this site knows, and anything that changes data
# is refused without it.
# ---------------------------------------------------------------

SAFE_METHODS = ("GET", "HEAD", "OPTIONS")


def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def check_csrf():
    if request.method in SAFE_METHODS:
        return None
    sent = (request.form.get("_csrf")
            or request.headers.get("X-CSRF-Token", ""))
    if not session.get("csrf") or not secrets.compare_digest(
            str(sent), str(session.get("csrf", ""))):
        audit_log.record((current_user() or {}).get("username", "anonymous"),
                         "csrf_blocked", request.path, request.remote_addr or "")
        if request.path.startswith("/seal"):
            return {"error": "Session expired. Reload the page."}, 400
        flash("That form expired. Please try again.", "bad")
        return redirect(request.referrer or url_for("dashboard"))
    return None


@app.context_processor
def inject_csrf():
    """Every template can drop {{ csrf_field() }} into a form."""
    from markupsafe import Markup
    token = csrf_token()
    return {"csrf_token": token,
            "csrf_field": lambda: Markup(
                '<input type="hidden" name="_csrf" value="%s">' % token)}


@app.context_processor
def inject_user():
    """Makes the signed in user available to every template."""
    return {"user": current_user(), "horizon": QUANTUM_HORIZON,
            "this_year": date.today().year}


def log(action, detail=""):
    u = current_user()
    audit_log.record(u["username"] if u else "anonymous", action, detail,
                     request.remote_addr or "")

SYSTEM_TYPES = ["Database", "Application", "Web Server", "Network",
                "Storage", "Email", "Other"]

DEPARTMENTS = [
    "Agriculture", "Civil Supplies", "Disaster Management", "Education",
    "Endowments", "Energy", "Excise", "Finance", "Fisheries", "Forest",
    "General Admin", "Handlooms", "Health", "Home", "IT & E-Gov",
    "Judiciary", "Labour", "Mines & Geology", "Municipal Admin",
    "Public Libraries", "Revenue", "Rural Development", "Sports & Youth",
    "Tourism", "Transport", "Women & Child", "Other", "Unassigned",
]


def form_options():
    """Everything the Add System form needs to build its dropdowns."""
    return {
        "departments": DEPARTMENTS,
        "types": SYSTEM_TYPES,
        "algorithms": sorted(CRYPTO_RULES.keys()),
        "sensitivities": list(SENSITIVITY_SCALE.keys()),
        "exposures": list(EXPOSURE_SCALE.keys()),
        "criticalities": list(CRITICALITY_SCALE.keys()),
    }


def validate(form):
    """Check the submitted form. Returns (cleaned_data, list_of_errors)."""
    errors = []

    name = form.get("name", "").strip()
    if not name:
        errors.append("System name is required.")
    elif len(name) > 80:
        errors.append("System name must be 80 characters or fewer.")

    dept = form.get("department", "")
    if dept not in DEPARTMENTS:
        errors.append("Choose a valid department.")

    stype = form.get("type", "")
    if stype not in SYSTEM_TYPES:
        errors.append("Choose a valid system type.")

    algorithm = form.get("algorithm", "")
    if algorithm not in CRYPTO_RULES:
        errors.append("Choose a valid cryptographic algorithm.")

    raw_key = form.get("key_size", "").strip()
    key_size = 0
    try:
        key_size = int(raw_key)
        if key_size < 1 or key_size > 100000:
            errors.append("Key size must be between 1 and 100000 bits.")
    except ValueError:
        errors.append("Key size must be a whole number.")

    sensitivity = form.get("sensitivity", "")
    if sensitivity not in SENSITIVITY_SCALE:
        errors.append("Choose a valid data sensitivity.")

    # Mosca's X: how long the data must stay secret.
    secrecy_years = 0
    try:
        secrecy_years = float(form.get("secrecy_years", "").strip())
        if secrecy_years < 0 or secrecy_years > 200:
            errors.append("Years the data must stay secret must be between 0 and 200.")
    except ValueError:
        errors.append("Enter how many years the data must stay secret.")

    # Mosca's Y: how long moving it to a new algorithm would take.
    migration_years = 0
    try:
        migration_years = float(form.get("migration_years", "").strip())
        if migration_years < 0 or migration_years > 20:
            errors.append("Migration time must be between 0 and 20 years.")
    except ValueError:
        errors.append("Enter how many years the migration would take.")

    exposure = form.get("exposure", "")
    if exposure not in EXPOSURE_SCALE:
        errors.append("Choose how exposed the system is.")

    criticality = form.get("criticality", "")
    if criticality not in CRITICALITY_SCALE:
        errors.append("Choose a valid system criticality.")

    data = {"name": name, "department": dept, "type": stype,
            "algorithm": algorithm,
            "key_size": key_size, "sensitivity": sensitivity,
            "criticality": criticality, "secrecy_years": secrecy_years,
            "migration_years": migration_years, "exposure": exposure}

    return data, errors


def audited():
    """Read the database and score everything. Used by most pages."""
    return audit_all(database.get_all_systems())


def overview(results):
    """The handful of facts every summary page needs."""
    late = [r for r in results if r["mosca_state"] == "late"]
    inside = [r for r in results if r["mosca_state"] == "inside"]
    safe = [r for r in results if r["mosca_state"] == "safe"]
    causes = {}
    for r in late:
        causes[r["algorithm"]] = causes.get(r["algorithm"], 0) + 1
    cause = max(causes.items(), key=lambda x: x[1]) if causes else None
    total = len(results) or 1
    return {"late": late, "inside": inside, "safe": safe, "cause": cause,
            "total": len(results),
            "late_pct": int(round(100.0 * len(late) / total))}


def algorithm_counts(results):
    counts = {}
    for r in results:
        counts[r["algorithm"]] = counts.get(r["algorithm"], 0) + 1
    return counts


@app.route("/")
@login_required
def dashboard():
    results = audited()
    expiring = [r for r in database.latest_scans()
                if r.get("days_left") is not None and 0 <= r["days_left"] <= 30]
    broken = [r for r in results if r["broken_now"]]
    ticks = database.remediation_counts()
    fixed = len([r for r in broken if ticks.get(r["id"], 0) >= 5])
    return render_template("dashboard.html", o=overview(results),
                           top=results[:5], expiring=expiring,
                           broken=broken, broken_fixed=fixed)


@app.route("/inventory")
@login_required
def inventory():
    results = audited()
    all_depts = departments(database.get_all_systems())

    query = request.args.get("q", "").strip()
    dept = request.args.get("dept", "")
    level = request.args.get("level", "")
    state = request.args.get("state", "")

    shown = results
    if query:
        q = query.lower()
        shown = [r for r in shown
                 if q in r["name"].lower()
                 or q in r.get("department", "").lower()
                 or q in r["algorithm"].lower()]
    if dept:
        shown = [r for r in shown if r.get("department") == dept]
    if level:
        shown = [r for r in shown if r["risk_level"] == level]
    if state:
        shown = [r for r in shown if r["mosca_state"] == state]

    return render_template("inventory.html",
                           results=shown,
                           total=len(results),
                           all_depts=all_depts,
                           query=query, dept=dept, level=level, state=state)


@app.route("/add", methods=["GET", "POST"])
@auditor_required
def add_system():
    if request.method == "POST":
        data, errors = validate(request.form)
        if errors:
            return render_template("add_system.html", errors=errors,
                                   form=data, **form_options())
        database.add_system(data)
        log("add", data["name"] + " (" + data["department"] + ") "
            + data["algorithm"] + "-" + str(data["key_size"]))
        flash("Added " + data["name"] + " to the inventory.", "ok")
        return redirect(url_for("inventory"))

    return render_template("add_system.html", errors=[], form={},
                           **form_options())


@app.route("/results")
@login_required
def audit_results():
    results = audited()
    all_depts = departments(database.get_all_systems())

    dept = request.args.get("dept", "")
    level = request.args.get("level", "")
    only = request.args.get("system", "")

    shown = results
    if dept:
        shown = [r for r in shown if r.get("department") == dept]
    if level:
        shown = [r for r in shown if r["risk_level"] == level]
    if only:
        shown = [r for r in shown if str(r["id"]) == only]

    return render_template("audit_results.html",
                           results=shown,
                           total=len(results),
                           all_systems=results,
                           all_depts=all_depts,
                           dept=dept, level=level, only=only,
                           weights=WEIGHTS, gap_cap=GAP_CAP)


@app.route("/analysis")
@login_required
def analysis():
    """The whole picture, answered as four plain questions."""
    results = audited()
    summary = summarise(results)
    total = len(results) or 1

    # Q1: how many are in trouble
    states = {
        "late": [r for r in results if r["mosca_state"] == "late"],
        "inside": [r for r in results if r["mosca_state"] == "inside"],
        "safe": [r for r in results if r["mosca_state"] == "safe"],
    }

    # Q2: what is causing it. AES is split by key size, because AES-128
    # and AES-256 have opposite answers.
    def lock_name(r):
        return "AES-%s" % r["key_size"] if r["algorithm"] == "AES" else r["algorithm"]

    colour_of = {"shor": "#E45A5A", "broken": "#B03A3A", "grover": "#D9C24A",
                 "safe": "#5AB98A", "pqc": "#5AB98A", "unknown": "#9A8FA8"}
    locks = {}
    for r in results:
        name = lock_name(r)
        entry = locks.setdefault(name, {"name": name, "count": 0, "late": 0,
                                        "status": r["crypto_status"],
                                        "label": r["crypto_status_label"]})
        entry["count"] += 1
        if r["mosca_state"] == "late":
            entry["late"] += 1
    locks = sorted(locks.values(), key=lambda x: (-x["count"], x["name"]))
    biggest = max(locks, key=lambda x: x["late"]) if locks else None

    depts = {}
    for r in states["late"]:
        depts[r["department"]] = depts.get(r["department"], 0) + 1
    worst_dept = max(depts.items(), key=lambda x: x[1]) if depts else None

    # Q3: does it depend on when quantum computers arrive
    scenarios, always_late = scenario_table(database.get_all_systems())

    # Q4: what to fix first
    top = results[:6]
    year = date.today().year
    for r in top:
        secret_until = year + int(round(r["secrecy_years"] + r["migration_years"]))
        if r["mosca_state"] == "late" and r["deadline_years"] == 0:
            r["why"] = "Lock is already broken today; data must stay secret until %d." % secret_until
        elif r["mosca_state"] == "late":
            r["why"] = "Must stay secret until %d; lock may break around %d." % (
                secret_until, year + r["deadline_years"])
        elif r["mosca_state"] == "inside":
            r["why"] = "Lock is quantum-vulnerable and exposed, but the data is short-lived."
        else:
            r["why"] = "Already quantum-safe."

    return render_template("analysis.html",
                           summary=summary, total=len(results),
                           states=states,
                           state_counts=[len(states["late"]), len(states["inside"]),
                                         len(states["safe"])],
                           pct=lambda n: int(round(100.0 * n / total)),
                           locks=locks, biggest=biggest, worst_dept=worst_dept,
                           lock_names=[l["name"] for l in locks],
                           lock_counts=[l["count"] for l in locks],
                           lock_colours=[colour_of.get(l["status"], "#9A8FA8") for l in locks],
                           scenarios=scenarios, always_late=always_late,
                           top=top,
                           top_names=[r["name"] for r in top],
                           top_scores=[r["risk_percentage"] for r in top])


@app.route("/plan")
@login_required
def migration_plan():
    results = audited()
    return render_template("plan.html",
                           phases=build_plan(results),
                           steps=MIGRATION_STEPS,
                           total=len(results))


@app.route("/report")
@login_required
def report():
    results = audited()
    return render_template("report.html",
                           results=results,
                           summary=summarise(results),
                           by_algorithm=algorithm_counts(results),
                           weights=WEIGHTS,
                           today=date.today().strftime("%d %B %Y"))


@app.route("/departments")
@login_required
def department_view():
    results = audited()
    groups = by_department(results)
    return render_template("departments.html",
                           groups=groups,
                           dept_names=[g["name"] for g in groups],
                           dept_averages=[g["average"] for g in groups])


@app.route("/import", methods=["GET", "POST"])
@auditor_required
def import_csv():
    if request.method == "POST":
        upload = request.files.get("file")
        if not upload or not upload.filename:
            return render_template("import.html",
                                   errors=["Choose a CSV file first."],
                                   loaded=0, problems=[])
        try:
            text = upload.read().decode("utf-8-sig")
        except UnicodeDecodeError:
            return render_template("import.html",
                                   errors=["That file is not readable as text. "
                                           "Save it as CSV, not xlsx."],
                                   loaded=0, problems=[])

        good, problems = csv_import.parse_csv(text)

        if good:
            database.add_many(good)
            log("import", "%d system(s) from %s, %d row(s) skipped"
                % (len(good), upload.filename, len(problems)))
            flash("Imported %d system(s) from %s."
                  % (len(good), upload.filename), "ok")

        return render_template("import.html", errors=[],
                               loaded=len(good), problems=problems)

    return render_template("import.html", errors=[], loaded=0, problems=[])


@app.route("/template.csv")
@login_required
def csv_template():
    return Response(csv_import.TEMPLATE, mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=systems-template.csv"})


@app.route("/export.csv")
@login_required
def export_csv():
    results = audited()
    lines = ["priority,name,department,type,algorithm,key_size,quantum_status,"
             "secrecy_years,migration_years,exposure,mosca_gap_years,"
             "risk_score,risk_level,replacement"]
    for r in results:
        lines.append('%d,"%s","%s","%s","%s",%s,"%s",%s,%s,"%s",%s,%s,"%s","%s"'
                     % (r["priority"], r["name"], r.get("department", ""),
                        r["type"], r["algorithm"], r["key_size"],
                        r["crypto_status_label"], r["secrecy_years"],
                        r["migration_years"], r["exposure"],
                        "" if r["gap_years"] is None else r["gap_years"],
                        r["risk_score"], r["risk_level"],
                        r["replacement"].replace('"', "'")))
    return Response("\n".join(lines), mimetype="text/csv",
                    headers={"Content-Disposition":
                             "attachment; filename=crypto-audit.csv"})


@app.route("/protect", methods=["GET", "POST"])
@login_required
def protect():
    """Enter a system and get a protection plan. Nothing is saved."""
    results = audited()

    # allow jumping straight here from a system already in the register
    existing = request.args.get("system", "")
    prefill = {}
    if existing:
        row = [r for r in results if str(r["id"]) == existing]
        if row:
            prefill = row[0]

    plan = None
    scored = None
    errors = []

    if request.method == "POST":
        data, errors = validate(request.form)
        if not errors:
            scored = calculate_risk(data)
            plan = advisory.build_advisory(data, scored)
            prefill = data
    elif prefill:
        scored = calculate_risk(prefill)
        plan = advisory.build_advisory(prefill, scored)

    target = None
    if scored and not scored.get("error"):
        from recommendation_engine import get_short_target
        target = get_short_target(scored["algorithm"], scored["key_size"])

    emergency, done = None, {}
    if scored and not scored.get("error") and scored.get("broken_now"):
        emergency = advisory.emergency_steps(scored)
        if scored.get("id"):
            done = database.steps_done(scored["id"])

    return render_template("protect.html",
                           plan=plan, scored=scored, errors=errors, target=target,
                           emergency=emergency, done=done,
                           form=prefill,
                           general=advisory.general_advisory(),
                           all_systems=results,
                           **form_options())


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        address = request.remote_addr or ""

        wait = auth.locked_out(username, address)
        if wait:
            audit_log.record(username or "unknown", "lockout",
                             "too many failed attempts", address)
            return render_template("login.html", first_password=FIRST_PASSWORD,
                                   error="Too many failed attempts. Wait %d minutes "
                                         "and try again." % wait)

        user = auth.check_password(username, password)
        if user:
            keep = session.get("csrf")
            session.clear()              # new session on sign in
            session["csrf"] = keep
            session["user"] = {"id": user["id"], "username": user["username"],
                               "role": user["role"]}
            auth.clear_failures(username, address)
            audit_log.record(user["username"], "login", "", address)
            flash("Signed in as " + user["username"] + ".", "ok")
            nxt = request.args.get("next") or url_for("dashboard")
            return redirect(nxt)

        auth.record_failure(username, address)
        audit_log.record(username or "unknown", "login_fail",
                         "wrong username or password", address)
        left = auth.MAX_ATTEMPTS - auth.recent_failures(username, address)
        return render_template("login.html", first_password=FIRST_PASSWORD,
                               error="Wrong username or password."
                                     + (" %d attempt(s) left." % left if 0 < left <= 2 else ""))

    if current_user():
        return redirect(url_for("dashboard"))
    return render_template("login.html", error=None,
                           first_password=FIRST_PASSWORD)


@app.route("/password", methods=["GET", "POST"])
@login_required
def password():
    """Change your own password."""
    if request.method == "POST":
        ok, message = auth.change_password(
            current_user()["id"],
            request.form.get("current", ""),
            request.form.get("new", ""),
            request.form.get("again", ""))
        if ok:
            log("password_change")
            flash("Password changed.", "ok")
            return redirect(url_for("dashboard"))
        return render_template("password.html", error=message)
    return render_template("password.html", error=None)


@app.route("/logout")
def logout():
    log("logout")
    session.pop("user", None)
    flash("Signed out.", "ok")
    return redirect(url_for("login"))


@app.route("/scan", methods=["GET", "POST"])
@auditor_required
def scan():
    """Read what a live server actually runs, instead of trusting a form."""
    results = []
    errors = []
    saved = 0

    if request.method == "POST":
        raw = request.form.get("hosts", "")
        hosts = [h.strip() for h in raw.replace(",", "\n").split("\n") if h.strip()]

        if not hosts:
            errors.append("Enter at least one hostname.")
        elif len(hosts) > 20:
            errors.append("Scan up to 20 hosts at a time.")
        else:
            results = scanner.scan_many(hosts)
            ok = [r for r in results if not r["error"]]
            # Keep every scan, including the failures. A host that stopped
            # answering is itself worth knowing about.
            for r in results:
                database.save_scan(r)
            log("scan", "%d host(s): %s" % (len(hosts), ", ".join(hosts[:5])))

            if request.form.get("save") and ok:
                dept = request.form.get("department", "Unassigned")
                sens = request.form.get("sensitivity", "Medium")
                crit = request.form.get("criticality", "Medium")
                try:
                    secrecy = float(request.form.get("secrecy_years", "5"))
                except ValueError:
                    secrecy = 5
                try:
                    migrate = float(request.form.get("migration_years", "1"))
                except ValueError:
                    migrate = 1
                for r in ok:
                    # Record what was measured. If the scanner could not
                    # identify it, the knowledge base flags it for review
                    # rather than this code guessing.
                    database.add_system({
                        "name": r["host"], "department": dept,
                        "type": "Web Server", "algorithm": r["algorithm"],
                        "key_size": r["key_size"], "sensitivity": sens,
                        "criticality": crit, "secrecy_years": secrecy,
                        "migration_years": migrate,
                        "exposure": "Public internet"})
                    saved += 1
                log("scan_save", "%d scanned host(s) added to the register" % saved)
                flash("Added %d scanned host(s) to the inventory." % saved, "ok")

    return render_template("scan.html", results=results, errors=errors,
                           saved=saved, **form_options())


@app.route("/expiry")
@login_required
def expiry():
    """Certificates running out. The one page that prevents an outage
       next month rather than a theft in 2036."""
    rows = database.latest_scans()

    def band(r):
        if r.get("error"):
            return "unreachable"
        d = r.get("days_left")
        if d is None:
            return "unknown"
        if d < 0:
            return "expired"
        if d <= 14:
            return "critical"
        if d <= 30:
            return "urgent"
        if d <= 90:
            return "soon"
        return "fine"

    for r in rows:
        r["band"] = band(r)

    counts = {}
    for key in ["expired", "critical", "urgent", "soon", "fine",
                "unreachable", "unknown"]:
        counts[key] = len([r for r in rows if r["band"] == key])

    return render_template("expiry.html", rows=rows, counts=counts,
                           total_scans=database.count_scans())


@app.route("/rescan", methods=["POST"])
@auditor_required
def rescan():
    """Scan every host we have ever scanned, again."""
    hosts = database.scanned_hosts()
    if not hosts:
        flash("Nothing has been scanned yet. Use the Scan page first.", "bad")
        return redirect(url_for("scan"))

    results = scanner.scan_many(hosts[:20])
    for r in results:
        database.save_scan(r)
    log("scan", "re-scanned %d host(s)" % len(results))
    flash("Re-scanned %d host(s)." % len(results), "ok")
    return redirect(url_for("expiry"))


@app.route("/history/<host>")
@login_required
def history(host):
    """What has changed on one host over time."""
    rows = database.scan_history(host)
    if not rows:
        flash("No scans recorded for " + host, "bad")
        return redirect(url_for("expiry"))
    return render_template("history.html", host=host, rows=rows)


@app.route("/subscribe", methods=["POST"])
@login_required
def subscribe():
    """Ask to be emailed before a host's certificate expires."""
    host = request.form.get("host", "")
    email = request.form.get("email", "")
    days = request.form.get("days_before", "30")
    ok, message = notifier.add_alert(host, email, days,
                                     created_by=(current_user() or {}).get("username", ""))
    if ok:
        log("alert_add", "%s -> %s at %s days" % (scanner.clean_host(host), email, days))
    flash(message, "ok" if ok else "bad")
    return redirect(request.form.get("back") or url_for("alerts"))


@app.route("/alerts", methods=["GET", "POST"])
@login_required
def alerts():
    """Everyone who has asked to be warned, and what was last sent."""
    report = None
    test_result = None

    if request.method == "POST":
        user = current_user() or {}
        action = request.form.get("action")

        if action == "delete":
            gone = notifier.delete_alert(int(request.form.get("id", 0)))
            if gone:
                log("alert_delete", "%s -> %s" % (gone["host"], gone["email"]))
                flash("Stopped emails to %s about %s." % (gone["email"], gone["host"]), "ok")

        elif action == "check":
            if user.get("role") != "auditor":
                flash("Only an auditor can run the check.", "bad")
            else:
                report = notifier.check_all()
                sent = len([e for e in report if e["sent"]])
                log("alert_check", "%d subscription(s) checked, %d email(s) sent"
                    % (len(report), sent))
                flash("Checked %d subscription(s), sent %d email(s)."
                      % (len(report), sent), "ok")

        elif action == "test":
            ok, where = notifier.send_test(request.form.get("email", ""))
            test_result = {"ok": ok, "where": where}
            if ok:
                log("alert_test", request.form.get("email", ""))

    latest = {r["host"]: r for r in database.latest_scans()}
    rows = notifier.list_alerts()
    for r in rows:
        scan = latest.get(r["host"])
        r["days_left"] = scan.get("days_left") if scan else None
        r["expires"] = scan.get("expires") if scan else None
        r["error"] = scan.get("error") if scan else None

    outbox = []
    if os.path.isdir(notifier.OUTBOX):
        outbox = sorted(os.listdir(notifier.OUTBOX), reverse=True)[:10]

    return render_template("alerts.html",
                           rows=rows, report=report, test_result=test_result,
                           mode=notifier.mode(), thresholds=notifier.THRESHOLDS,
                           outbox=outbox, outbox_dir=notifier.OUTBOX)


@app.route("/outbox/<name>")
@login_required
def outbox_file(name):
    """Show a saved email, so outbox mode can be checked in the browser."""
    safe = os.path.basename(name)
    path = os.path.join(notifier.OUTBOX, safe)
    if not safe.endswith(".eml") or not os.path.exists(path):
        flash("That email is not in the outbox.", "bad")
        return redirect(url_for("alerts"))
    with open(path, encoding="utf-8") as f:
        text = f.read()
    return render_template("outbox.html", name=safe, text=text)


@app.route("/remediate", methods=["POST"])
@auditor_required
def remediate():
    """Tick or untick one emergency step for one system."""
    try:
        system_id = int(request.form.get("system_id", 0))
        step = int(request.form.get("step", 0))
    except ValueError:
        return redirect(url_for("protect"))
    system = database.get_system(system_id)
    if system and 1 <= step <= 5:
        done = request.form.get("done") == "1"
        database.set_step(system_id, step, done, current_user()["username"])
        log("remediate", "%s: step %d %s" % (system["name"], step,
                                           "done" if done else "undone"))
    return redirect(url_for("protect", system=system_id) + "#emergency")


# ---------------------------------------------------------------
# Re-sealing documents whose old seal (SHA-1, MD5) can be forged.
#
# The document never reaches the server. The browser works out its
# SHA-384 fingerprint and sends only that. The server signs the
# fingerprint with whatever the crypto policy says, and hands back a
# small .seal file. Later, anyone can check a document against its seal.
# ---------------------------------------------------------------

def _seal_text(seal):
    return "\n".join(["UC027-SEAL-v1", seal["document"], str(seal["size"]),
                      seal["sha384"], seal["sealed_at"], seal["sealed_by"],
                      seal.get("system", "")])


def _valid_hex(h, length):
    return (isinstance(h, str) and len(h) == length
            and all(c in "0123456789abcdef" for c in h))


@app.route("/seal", methods=["POST"])
@login_required
def seal_document():
    import datetime as _dt
    data = request.get_json(silent=True) or {}
    sha = str(data.get("sha384", "")).lower()
    name = str(data.get("name", ""))[:200]
    try:
        size = int(data.get("size", -1))
    except (TypeError, ValueError):
        size = -1
    if not name or size < 0 or not _valid_hex(sha, 96):
        return {"error": "That does not look like a document fingerprint."}, 400

    seal = {
        "document": name,
        "size": size,
        "sha384": sha,
        "sealed_at": _dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "sealed_by": current_user()["username"],
        "system": str(data.get("system", ""))[:120],
    }
    seal["signature"] = crypto_service.sign(_seal_text(seal))
    seal["algorithm"] = "SHA-384 fingerprint, signed with " + seal["signature"].split(".")[0]
    log("seal", "%s (%d bytes)%s" % (name, size,
                                     " for " + seal["system"] if seal["system"] else ""))
    return seal


@app.route("/seal/verify", methods=["POST"])
@login_required
def verify_seal():
    data = request.get_json(silent=True) or {}
    seal = data.get("seal") or {}
    needed = ("document", "size", "sha384", "sealed_at", "sealed_by", "signature")
    if not all(k in seal for k in needed):
        return {"genuine": False, "reason": "That is not a seal file from this site."}
    genuine = crypto_service.verify(_seal_text(seal), seal["signature"])
    return {"genuine": genuine,
            "reason": "" if genuine else "The seal itself has been altered or was not made here."}


@app.route("/code", methods=["GET", "POST"])
@login_required
def code():
    """Find old locks inside source code. Nothing is stored."""
    findings, summary, notes, name, scanned = [], None, [], "", 0

    if request.method == "POST":
        upload = request.files.get("file")
        if not upload or not upload.filename:
            notes = ["Choose a file first."]
        else:
            name = upload.filename
            data = upload.read()
            if len(data) > 20 * 1024 * 1024:
                notes = ["That file is over 20 MB."]
            else:
                findings, scanned, notes = code_scan.scan_upload(name, data)
                summary = code_scan.summarise(findings)
                log("code_scan", "%s: %d file(s), %d finding(s)"
                    % (name, scanned, len(findings)))

    return render_template("code.html", findings=findings, summary=summary,
                           notes=notes, name=name, scanned=scanned)


@app.route("/cbom.json")
@login_required
def cbom_export():
    """The inventory as a Cryptographic Bill of Materials (CycloneDX 1.6)."""
    import json
    bom = cbom.build_cbom(audited(), database.latest_scans())
    log("export", "CBOM with %d components" % len(bom["components"]))
    return Response(json.dumps(bom, indent=2), mimetype="application/json",
                    headers={"Content-Disposition":
                             "attachment; filename=crypto-bom.cdx.json"})


@app.route("/agility", methods=["GET", "POST"])
@login_required
def agility():
    """Crypto-agility, measured on this application itself."""
    sign_result = None

    if request.method == "POST":
        action = request.form.get("action")
        user = current_user() or {}

        if action == "policy":
            if user.get("role") != "auditor":
                flash("Only an auditor can change the crypto policy.", "bad")
            else:
                before = crypto_service.load_policy()
                wanted = {k: request.form.get(k, before[k]) for k in before}
                ok, message = crypto_service.save_policy(wanted)
                if ok:
                    changed = ["%s: %s -> %s" % (k, before[k], wanted[k])
                               for k in before if before[k] != wanted[k]]
                    log("policy_change", "; ".join(changed) or "no change")
                    flash("Policy saved. " + ("Changed " + "; ".join(changed)
                          if changed else "Nothing changed.") +
                          " No application code was touched.", "ok")
                else:
                    flash(message, "bad")
            return redirect(url_for("agility"))

        if action in ("sign", "verify"):
            text = request.form.get("text", "")
            token = request.form.get("token", "").strip()
            if action == "sign" and text:
                token = crypto_service.sign(text)
                sign_result = {"text": text, "token": token, "made": True,
                               "valid": crypto_service.verify(text, token)}
            elif action == "verify" and text and token:
                sign_result = {"text": text, "token": token, "made": False,
                               "valid": crypto_service.verify(text, token)}

    policy = crypto_service.load_policy()
    sites = crypto_service.hardcoded_call_sites(os.path.dirname(os.path.abspath(__file__)))
    hashes = auth.password_algorithms()
    on_policy = hashes.get(policy["password_hash"], 0)

    scans = [r for r in database.latest_scans() if r.get("lifetime_days")]
    short = [r for r in scans if r["lifetime_days"] <= 90]

    changes = audit_log.recent(10, action="policy_change")

    return render_template("agility.html",
                           policy=policy,
                           passwords=crypto_service.PASSWORD_ALGORITHMS,
                           signatures=crypto_service.SIGNATURE_ALGORITHMS,
                           pending=crypto_service.PQC_SIGNATURES_PENDING,
                           cert_keys=crypto_service.CERT_KEY_ALGORITHMS,
                           sites=sites, hashes=hashes, on_policy=on_policy,
                           total_users=sum(hashes.values()),
                           scans=scans, short=short, changes=changes,
                           sign_result=sign_result)


@app.route("/log")
@login_required
def view_log():
    action = request.args.get("action", "")
    entries = audit_log.recent(300, action=action or None)
    return render_template("log.html",
                           entries=entries,
                           summary=audit_log.summary(),
                           actions=audit_log.ACTIONS,
                           label=audit_log.label,
                           action=action)


@app.route("/users", methods=["GET", "POST"])
@auditor_required
def users():
    error = None
    if request.method == "POST":
        if request.form.get("delete_id"):
            uid = int(request.form["delete_id"])
            me = current_user()
            if me and me["id"] == uid:
                error = "You cannot delete the account you are signed in as."
            else:
                gone = [u for u in auth.list_users() if u["id"] == uid]
                auth.delete_user(uid)
                log("user_delete", gone[0]["username"] if gone else str(uid))
                flash("Account removed.", "ok")
        else:
            ok, message = auth.add_user(request.form.get("username", ""),
                                        request.form.get("password", ""),
                                        request.form.get("role", "viewer"))
            if ok:
                log("user_add", request.form.get("username", "")
                    + " as " + request.form.get("role", "viewer"))
                flash(message, "ok")
            else:
                error = message

    return render_template("users.html", users=auth.list_users(),
                           roles=auth.ROLES, error=error)


@app.route("/delete/<int:system_id>", methods=["POST"])
@auditor_required
def delete_system(system_id):
    system = database.get_system(system_id)
    if system:
        database.delete_system(system_id)
        log("delete", system["name"] + " (" + system.get("department", "") + ")")
        flash("Removed " + system["name"] + " from the inventory.", "ok")
    return redirect(url_for("inventory"))


# ---------------------------------------------------------------
# Starting up
#
#   python app.py              just this machine, over http
#   python app.py --network    reachable by other machines on the network
#   python app.py --https      over https, needs: python make_cert.py first
#   python app.py --network --https --port 8443
# ---------------------------------------------------------------

def parse_args(argv):
    opts = {"host": "127.0.0.1", "port": 5000, "https": False, "debug": True}
    for i, a in enumerate(argv):
        if a in ("--network", "-n"):
            opts["host"] = "0.0.0.0"
        elif a in ("--https", "-s"):
            opts["https"] = True
        elif a in ("--quiet", "-q"):
            opts["debug"] = False
        elif a == "--port" and i + 1 < len(argv):
            try:
                opts["port"] = int(argv[i + 1])
            except ValueError:
                pass
    return opts


def my_addresses():
    """Every address this machine can be reached on."""
    import socket
    found = ["127.0.0.1"]
    try:
        # Asking the routing table which address would be used to reach
        # the internet is more reliable than gethostbyname on Windows.
        probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        probe.settimeout(0.4)
        probe.connect(("8.8.8.8", 80))
        found.append(probe.getsockname()[0])
        probe.close()
    except Exception:
        try:
            for info in socket.getaddrinfo(socket.gethostname(), None,
                                           socket.AF_INET):
                addr = info[4][0]
                if addr not in found:
                    found.append(addr)
        except Exception:
            pass
    return found


if __name__ == "__main__":
    import sys

    opts = parse_args(sys.argv[1:])
    scheme = "https" if opts["https"] else "http"
    context = None

    if opts["https"]:
        cert, keyfile = os.path.join("certs", "site.crt"), os.path.join("certs", "site.key")
        if not (os.path.exists(cert) and os.path.exists(keyfile)):
            print("")
            print("No certificate found. Make one first:")
            print("   python make_cert.py")
            print("")
            raise SystemExit(1)
        context = (cert, keyfile)

    print("")
    print("=" * 62)
    print("CRYPTO AUDIT SYSTEM")
    print("=" * 62)
    print("  Systems in the register : %d" % database.count_systems())
    print("  Accounts               : %d" % auth.count_users())
    if FIRST_PASSWORD:
        print("")
        print("  FIRST RUN. Sign in with:")
        print("     username: admin")
        print("     password: " + FIRST_PASSWORD)
        print("     Make your own account under Accounts, then delete this one.")
    print("")
    print("  Open:")
    if opts["host"] == "0.0.0.0":
        for addr in my_addresses():
            print("     %s://%s:%d" % (scheme, addr, opts["port"]))
        print("")
        print("  Other machines on this network can use the second address.")
        print("  If they cannot, Windows Firewall is blocking the port. Run this")
        print("  once in an Administrator command prompt:")
        print("     netsh advfirewall firewall add rule name=\"Crypto Audit\" "
              "dir=in action=allow protocol=TCP localport=%d" % opts["port"])
    else:
        print("     %s://127.0.0.1:%d" % (scheme, opts["port"]))
        print("")
        print("  Only this machine can reach it. For others on the network:")
        print("     python app.py --network")
    if not opts["https"]:
        print("")
        print("  Running over plain http. For https:")
        print("     python make_cert.py")
        print("     python app.py --https")
    print("")
    print("  Stop with Ctrl+C")
    print("=" * 62)
    print("")

    app.run(host=opts["host"], port=opts["port"],
            debug=opts["debug"], ssl_context=context)
