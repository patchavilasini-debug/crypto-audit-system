# recommendation_engine.py
# Ranking, advice, and the migration roadmap.
#
# UC-027 targets: move long-secrecy systems first, and move them to the
# NIST post-quantum standards - ML-KEM (FIPS 203) for key exchange,
# ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) for signatures - using hybrid
# modes first because they stay compatible with older clients.

from risk_engine import calculate_risk, fill_defaults, SCENARIOS

RECOMMENDATIONS = {
    "Critical": "Already past its quantum deadline or close to it. Start hybrid migration now.",
    "High": "Quantum-vulnerable with real exposure. Plan the post-quantum migration this year.",
    "Medium": "Include in the post-quantum migration plan at the next refresh.",
    "Low": "No action needed now. Review at the annual audit.",
}

HYBRID = "Hybrid X25519 + ML-KEM-768 now (FIPS 203), pure ML-KEM once every client supports it"
SIGNING = "ML-DSA-65 (FIPS 204), or SLH-DSA (FIPS 205) for very long-lived signatures"

# What each algorithm should become. Keyed by the knowledge-base name.
REPLACEMENTS = {
    "RSA": "Key exchange: " + HYBRID + ". Signatures: " + SIGNING + ".",
    "ECC": "Key exchange: " + HYBRID + ". Signatures: " + SIGNING + ".",
    "DH": HYBRID + ".",
    "3DES": "AES-256-GCM.",
    "DES": "AES-256-GCM.",
    "RC4": "AES-256-GCM.",
    "SHA-1": "SHA-384. Re-sign anything signed with SHA-1.",
    "MD5": "SHA-384.",
    "SHA-256": "SHA-384 for data kept past 2035. SHA-256 is acceptable otherwise.",
    "SHA-384": "No change needed.",
    "ML-KEM": "Already post-quantum. Keep under review.",
    "ML-DSA": "Already post-quantum. Keep under review.",
    "SLH-DSA": "Already post-quantum. Keep under review.",
    "X25519-MLKEM": "Already post-quantum (hybrid). Move to pure ML-KEM when clients allow.",
}

MIGRATION_STEPS = [
    ["Map dependencies",
     "List every application, service and partner that touches this system."],
    ["Go hybrid first",
     "Add ML-KEM alongside the current algorithm, so old clients keep working."],
    ["Test in a copy",
     "Prove the replacement works before anything in production changes."],
    ["Route it through the crypto service",
     "So the next change is a policy edit, not another migration project."],
    ["Re-encrypt what is stored",
     "New records are not enough. Old ones still sit under the old key."],
    ["Retire the old algorithm",
     "Remove the fallback, revoke the old keys, and re-scan to confirm."],
]

TIMEFRAMES = {
    "Critical": "Start within 3 months",
    "High": "Within 12 months",
    "Medium": "At the next scheduled refresh",
    "Low": "No action, review annually",
}


def get_recommendation(level):
    return RECOMMENDATIONS.get(level, "Review this system manually.")


def get_replacement(algorithm, key_size=None):
    from crypto_rules import normalise
    name = normalise(algorithm)
    if name == "AES":
        try:
            if int(key_size) >= 256:
                return "No change needed. AES-256 is quantum-safe."
        except (TypeError, ValueError):
            pass
        return "AES-256-GCM. Grover halves AES-128, so the fix is a bigger key."
    return REPLACEMENTS.get(name, "Review manually and choose a replacement.")


SHORT_TARGETS = {
    "RSA": "ML-KEM + ML-DSA", "ECC": "ML-KEM + ML-DSA", "DH": "ML-KEM",
    "3DES": "AES-256", "DES": "AES-256", "RC4": "AES-256",
    "SHA-1": "SHA-384", "MD5": "SHA-384", "SHA-256": "SHA-384",
}


def get_short_target(algorithm, key_size=None):
    """Two or three words, for tables. The full advice is on Protect."""
    from crypto_rules import normalise, get_crypto_risk
    name = normalise(algorithm)
    if not get_crypto_risk(name, key_size)["vulnerable"] and name != "SHA-256":
        return "Keep"
    if name == "AES":
        return "AES-256"
    return SHORT_TARGETS.get(name, "Review")


def get_timeframe(level):
    return TIMEFRAMES.get(level, "Review manually.")


def audit_all(systems, horizon=None):
    """Score every system, sort worst first, and number them.
       The number IS the migration priority."""
    results = []
    for s in systems:
        r = calculate_risk(s, horizon)
        if r.get("error"):
            continue
        r["recommendation"] = get_recommendation(r["risk_level"])
        r["replacement"] = get_replacement(r["algorithm"], r["key_size"])
        r["target"] = get_short_target(r["algorithm"], r["key_size"])
        r["timeframe"] = get_timeframe(r["risk_level"])
        results.append(r)

    results.sort(key=lambda x: x["risk_score"], reverse=True)
    for i, r in enumerate(results, start=1):
        r["priority"] = i
    return results


def departments(systems):
    """Every department name we know about, sorted."""
    return sorted(set(s.get("department", "Unassigned") for s in systems))


def by_department(results):
    """Risk grouped by department, worst average first."""
    groups = {}
    for r in results:
        groups.setdefault(r.get("department", "Unassigned"), []).append(r)

    out = []
    for name, rows in groups.items():
        count = {lvl: len([x for x in rows if x["risk_level"] == lvl])
                 for lvl in ("Critical", "High", "Medium", "Low")}
        out.append({
            "name": name,
            "count": len(rows),
            "critical": count["Critical"],
            "high": count["High"],
            "medium": count["Medium"],
            "low": count["Low"],
            "late": len([x for x in rows if x["mosca_state"] == "late"]),
            "inside": len([x for x in rows if x["mosca_state"] == "inside"]),
            "safe": len([x for x in rows if x["mosca_state"] == "safe"]),
            "worst": max(x["risk_percentage"] for x in rows),
            "average": round(sum(x["risk_percentage"] for x in rows) / len(rows), 1),
        })
    out.sort(key=lambda x: x["average"], reverse=True)
    return out


def summarise(results):
    summary = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for r in results:
        summary[r["risk_level"]] += 1
    summary["total"] = len(results)
    summary["review_needed"] = len([r for r in results if r["review_needed"]])
    summary["late"] = len([r for r in results if r["mosca_state"] == "late"])
    summary["vulnerable"] = len([r for r in results if r["quantum_vulnerable"]])
    summary["safe"] = len([r for r in results if not r["quantum_vulnerable"]])
    summary["broken_now"] = len([r for r in results if r["broken_now"]])
    return summary


def scenario_table(systems):
    """How many systems fail Mosca under each quantum-arrival guess.
       Systems that fail under all of them are the genuinely urgent ones."""
    rows = []
    failing_sets = []
    for label, years in SCENARIOS:
        res = audit_all(systems, horizon=years)
        late = [r["name"] for r in res if r["mosca_state"] == "late"]
        failing_sets.append(set(late))
        rows.append({"label": label, "years": years, "late": len(late),
                     "critical": len([r for r in res if r["risk_level"] == "Critical"])})
    always = set.intersection(*failing_sets) if failing_sets else set()
    return rows, sorted(always)


def build_plan(results):
    """
    Three funding phases, taken from Mosca rather than chosen by hand.

      Phase 1  already past the deadline - every year of delay adds to
               what can be read later
      Phase 2  quantum-vulnerable but still inside the window
      Phase 3  already quantum-safe, or low risk - routine refresh
    """
    phases = [
        {"number": 1, "title": "Stop the harvest", "window": "Start within 3 months",
         "aim": "These are already past Mosca's deadline: their data outlives their "
                "encryption, so anything copied today will be readable later. "
                "Go hybrid first so nothing breaks."},
        {"number": 2, "title": "Close the gap", "window": "Within 1 to 3 years",
         "aim": "Quantum-vulnerable but still inside the window. Migrate properly, "
                "and route each one through the crypto service so it never needs "
                "a project like this again."},
        {"number": 3, "title": "Routine refresh", "window": "3 years and beyond",
         "aim": "Already quantum-safe or low risk. No emergency spend; fold into "
                "upgrades and contract renewals that are happening anyway."},
    ]
    phases[0]["systems"] = [r for r in results if r["mosca_state"] == "late"]
    phases[1]["systems"] = [r for r in results if r["mosca_state"] == "inside"]
    phases[2]["systems"] = [r for r in results if r["mosca_state"] == "safe"]

    for p in phases:
        p["effort"] = round(sum(r["migration_years"] for r in p["systems"]), 1)
        p["worst_gap"] = max([r["gap_years"] for r in p["systems"]
                              if r["gap_years"] is not None] or [0])
    return phases


def sys_(name, dept, stype, algo, key, sens, life, crit):
    """Shorthand so the sample list below stays readable. Secrecy years,
       migration years and exposure are filled from sensible defaults."""
    return fill_defaults({"name": name, "department": dept, "type": stype,
                          "algorithm": algo, "key_size": key,
                          "sensitivity": sens, "lifetime": life,
                          "criticality": crit})


SAMPLE_SYSTEMS = [
    # Revenue
    sys_("Land Registry Database", "Revenue", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Registrar Signing Key", "Revenue", "Other", "ECC", 192, "Critical", "More than 10 years", "Critical"),
    sys_("Property Tax Portal", "Revenue", "Web Server", "RSA", 2048, "High", "5-10 years", "High"),

    # Health
    sys_("Patient Records", "Health", "Database", "RSA", 2048, "Critical", "More than 10 years", "High"),
    sys_("Hospital Imaging Store", "Health", "Storage", "AES", 128, "Critical", "More than 10 years", "Medium"),
    sys_("Appointment Booking", "Health", "Application", "ECC", 256, "Medium", "1-5 years", "Medium"),

    # Finance
    sys_("Treasury Payments", "Finance", "Application", "RSA", 3072, "Critical", "5-10 years", "Critical"),
    sys_("Staff Payroll", "Finance", "Application", "AES", 256, "Medium", "1-5 years", "Medium"),
    sys_("e-Procurement Portal", "Finance", "Web Server", "ECC", 256, "Medium", "1-5 years", "High"),
    sys_("Pension Disbursement", "Finance", "Database", "3DES", 168, "High", "More than 10 years", "High"),

    # Home
    sys_("Police Case Management", "Home", "Database", "ECC", 256, "Critical", "More than 10 years", "High"),
    sys_("CCTV Archive", "Home", "Storage", "AES", 128, "High", "5-10 years", "Medium"),
    sys_("Emergency Dispatch", "Home", "Network", "DH", 2048, "High", "1-5 years", "Critical"),

    # IT and e-Governance
    sys_("Citizen Identity Store", "IT & E-Gov", "Database", "AES", 128, "Critical", "More than 10 years", "Critical"),
    sys_("State Certificate Authority", "IT & E-Gov", "Other", "RSA", 4096, "Critical", "5-10 years", "Critical"),
    sys_("Secretariat VPN", "IT & E-Gov", "Network", "DH", 2048, "High", "5-10 years", "High"),
    sys_("Departmental Mail Server", "IT & E-Gov", "Email", "SHA-1", 160, "Medium", "1-5 years", "High"),

    # Civil Supplies
    sys_("Ration Card Database", "Civil Supplies", "Database", "3DES", 168, "High", "5-10 years", "High"),
    sys_("Warehouse Stock System", "Civil Supplies", "Application", "AES", 256, "Low", "1-5 years", "Medium"),

    # Education
    sys_("Student Examination Records", "Education", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Scholarship Payments", "Education", "Application", "RSA", 3072, "High", "5-10 years", "Medium"),

    # Transport
    sys_("Vehicle Registration", "Transport", "Database", "RSA", 2048, "Medium", "More than 10 years", "High"),
    sys_("Toll Collection", "Transport", "Application", "AES", 256, "Low", "Less than 1 year", "Medium"),

    # Tourism
    sys_("Tourism Website", "Tourism", "Web Server", "X25519-MLKEM", 768, "Low", "Less than 1 year", "Low"),
    sys_("Legacy Booking Archive", "Tourism", "Storage", "MD5", 128, "Low", "1-5 years", "Low"),

    # Municipal Administration
    sys_("Birth and Death Register", "Municipal Admin", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Property Tax Collection", "Municipal Admin", "Application", "RSA", 3072, "High", "5-10 years", "High"),
    sys_("Water Billing System", "Municipal Admin", "Application", "AES", 256, "Medium", "5-10 years", "Medium"),

    # Agriculture
    sys_("Farmer Subsidy Register", "Agriculture", "Database", "RSA", 2048, "High", "5-10 years", "High"),
    sys_("Crop Insurance Claims", "Agriculture", "Application", "ECC", 256, "High", "5-10 years", "High"),
    sys_("Soil Survey Archive", "Agriculture", "Storage", "AES", 128, "Low", "More than 10 years", "Low"),

    # Judiciary
    sys_("Case Records Repository", "Judiciary", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Court Order Signing Key", "Judiciary", "Other", "ECC", 256, "Critical", "More than 10 years", "Critical"),
    sys_("Cause List Publisher", "Judiciary", "Web Server", "ECC", 256, "Low", "Less than 1 year", "Medium"),

    # Labour and Employment
    sys_("Provident Fund Records", "Labour", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Employment Exchange", "Labour", "Application", "AES", 256, "Medium", "1-5 years", "Medium"),

    # Energy
    sys_("SCADA Control Network", "Energy", "Network", "DH", 1024, "High", "5-10 years", "Critical"),
    sys_("Consumer Meter Data", "Energy", "Database", "AES", 256, "Medium", "5-10 years", "High"),

    # Excise
    sys_("Licence Register", "Excise", "Database", "RSA", 3072, "Medium", "5-10 years", "Medium"),
    sys_("Duty Payment Gateway", "Excise", "Application", "ECC", 256, "High", "1-5 years", "High"),

    # General Administration
    sys_("Cabinet Note Circulation", "General Admin", "Email", "SHA-1", 160, "Critical", "More than 10 years", "Critical"),
    sys_("Personnel Records", "General Admin", "Database", "AES", 256, "High", "More than 10 years", "Medium"),
    sys_("Internal File Tracking", "General Admin", "Application", "AES", 256, "Low", "1-5 years", "Medium"),

    # Rural Development
    sys_("Panchayat Fund Ledger", "Rural Development", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Job Card Register", "Rural Development", "Database", "3DES", 168, "High", "5-10 years", "High"),

    # Women and Child Welfare
    sys_("Beneficiary Database", "Women & Child", "Database", "RSA", 2048, "Critical", "More than 10 years", "High"),
    sys_("Nutrition Scheme Records", "Women & Child", "Application", "AES", 256, "Medium", "5-10 years", "Medium"),

    # Public information - genuinely low risk, included so the Low band is not empty
    sys_("Press Release Portal", "General Admin", "Web Server", "AES", 256, "Low", "Less than 1 year", "Low"),
    sys_("Tender Notice Board", "Finance", "Web Server", "AES", 256, "Low", "Less than 1 year", "Low"),
    sys_("Museum Ticketing", "Tourism", "Application", "AES", 256, "Low", "Less than 1 year", "Low"),

    # Forest
    sys_("Wildlife Offence Register", "Forest", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Timber Permit System", "Forest", "Application", "AES", 256, "Medium", "5-10 years", "Medium"),
    sys_("Forest Boundary Maps", "Forest", "Storage", "AES", 128, "Medium", "More than 10 years", "Medium"),

    # Fisheries
    sys_("Fishing Licence Register", "Fisheries", "Database", "RSA", 3072, "Medium", "5-10 years", "Medium"),
    sys_("Boat Registration", "Fisheries", "Database", "RSA", 2048, "Medium", "More than 10 years", "Medium"),

    # Mines and Geology
    sys_("Mining Lease Records", "Mines & Geology", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Royalty Payment Gateway", "Mines & Geology", "Application", "ECC", 256, "High", "5-10 years", "High"),
    sys_("Survey Data Archive", "Mines & Geology", "Storage", "3DES", 168, "Medium", "More than 10 years", "Low"),

    # Endowments
    sys_("Temple Trust Accounts", "Endowments", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Donation Receipts", "Endowments", "Application", "AES", 256, "Medium", "5-10 years", "Medium"),

    # Disaster Management
    sys_("Emergency Alert Network", "Disaster Management", "Network", "DH", 2048, "High", "1-5 years", "Critical"),
    sys_("Relief Beneficiary List", "Disaster Management", "Database", "AES", 128, "High", "5-10 years", "High"),
    sys_("Cyclone Warning Portal", "Disaster Management", "Web Server", "X25519-MLKEM", 768, "Low", "Less than 1 year", "Critical"),

    # Sports and Youth
    sys_("Athlete Medical Records", "Sports & Youth", "Database", "RSA", 2048, "High", "More than 10 years", "Medium"),
    sys_("Stadium Booking", "Sports & Youth", "Application", "AES", 256, "Low", "1-5 years", "Low"),

    # Handlooms and Textiles
    sys_("Weaver Subsidy Register", "Handlooms", "Database", "RSA", 2048, "Medium", "5-10 years", "Medium"),
    sys_("Cooperative Accounts", "Handlooms", "Application", "3DES", 168, "Medium", "5-10 years", "Medium"),

    # Public Libraries
    sys_("Member Records", "Public Libraries", "Database", "AES", 256, "Low", "1-5 years", "Low"),
    sys_("Digital Archive", "Public Libraries", "Storage", "SHA-256", 256, "Low", "More than 10 years", "Low"),

    # Municipal Admin, more
    sys_("Trade Licence Register", "Municipal Admin", "Database", "RSA", 2048, "Medium", "5-10 years", "Medium"),
    sys_("Street Light Maintenance", "Municipal Admin", "Application", "AES", 256, "Low", "1-5 years", "Low"),
    sys_("Building Plan Approvals", "Municipal Admin", "Database", "ECC", 256, "High", "More than 10 years", "High"),

    # Health, more
    sys_("Blood Bank Register", "Health", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Vaccination Records", "Health", "Database", "AES", 128, "High", "More than 10 years", "High"),
    sys_("Drug Inventory", "Health", "Application", "AES", 256, "Low", "1-5 years", "Medium"),
    sys_("Ambulance Dispatch", "Health", "Network", "DH", 2048, "Medium", "1-5 years", "Critical"),

    # Home, more
    sys_("Fingerprint Database", "Home", "Database", "RSA", 2048, "Critical", "More than 10 years", "Critical"),
    sys_("Prison Records", "Home", "Database", "ECC", 256, "Critical", "More than 10 years", "High"),
    sys_("Traffic Challan System", "Home", "Application", "AES", 256, "Low", "5-10 years", "Medium"),

    # Revenue, more
    sys_("Encumbrance Certificates", "Revenue", "Database", "RSA", 2048, "High", "More than 10 years", "High"),
    sys_("Stamp Duty Collection", "Revenue", "Application", "ECC", 256, "High", "5-10 years", "High"),

    # Finance, more
    sys_("Budget Allocation System", "Finance", "Application", "RSA", 3072, "High", "5-10 years", "Critical"),
    sys_("Audit Objection Register", "Finance", "Database", "AES", 256, "Medium", "More than 10 years", "Medium"),
    sys_("GST Reconciliation", "Finance", "Application", "SHA-1", 160, "High", "5-10 years", "High"),

    # IT and E-Gov, more
    sys_("Single Sign On Service", "IT & E-Gov", "Application", "RSA", 2048, "Critical", "1-5 years", "Critical"),
    sys_("Document Signing Service", "IT & E-Gov", "Other", "ML-DSA", 65, "Critical", "More than 10 years", "Critical"),
    sys_("Public Wifi Portal", "IT & E-Gov", "Network", "RC4", 128, "Low", "Less than 1 year", "Low"),
    sys_("Backup Vault", "IT & E-Gov", "Storage", "AES", 256, "Critical", "More than 10 years", "High"),
]


if __name__ == "__main__":
    results = audit_all(SAMPLE_SYSTEMS)
    sm = summarise(results)
    print("=" * 84)
    print("UC-027 AUDIT - HARVEST NOW, DECRYPT LATER")
    print("=" * 84)
    print("%-4s %-28s %-17s %7s %6s  %s" % ("PRI", "SYSTEM", "CRYPTO", "MOSCA", "RISK", "LEVEL"))
    print("-" * 84)
    for r in results[:12]:
        gap = "safe" if r["gap_years"] is None else "%+.0f yr" % r["gap_years"]
        print("%-4d %-28s %-17s %7s %6.1f  %s" % (
            r["priority"], r["name"][:28], "%s-%s" % (r["algorithm"], r["key_size"]),
            gap, r["risk_score"], r["risk_level"]))
    print("   ...")
    for r in results[-3:]:
        gap = "safe" if r["gap_years"] is None else "%+.0f yr" % r["gap_years"]
        print("%-4d %-28s %-17s %7s %6.1f  %s" % (
            r["priority"], r["name"][:28], "%s-%s" % (r["algorithm"], r["key_size"]),
            gap, r["risk_score"], r["risk_level"]))
    print("")
    print("Total %d | Critical %d | High %d | Medium %d | Low %d" % (
        sm["total"], sm["Critical"], sm["High"], sm["Medium"], sm["Low"]))
    print("Past Mosca deadline %d | quantum-vulnerable %d | quantum-safe %d | broken today %d" % (
        sm["late"], sm["vulnerable"], sm["safe"], sm["broken_now"]))
    print("")
    rows, always = scenario_table(SAMPLE_SYSTEMS)
    for row in rows:
        print("  %-11s quantum in %2d yr -> %2d past deadline" % (row["label"], row["years"], row["late"]))
    print("  Fail under every scenario: %d systems" % len(always))
    print("")
    for p in build_plan(results):
        print("Phase %d  %-17s %2d systems, %5.1f years of migration effort" % (
            p["number"], p["title"], len(p["systems"]), p["effort"]))
