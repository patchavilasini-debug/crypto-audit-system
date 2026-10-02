# risk_engine.py
# Scoring, following UC-027.
#
# The core is Mosca's inequality:
#
#     X  +  Y  >  Z   means you are already too late
#
#     X  years the data must stay secret
#     Y  years it will take to migrate the system
#     Z  years until a quantum computer can break the algorithm
#
# If the data outlives its own encryption, anything copied today will be
# readable later. That is harvest now, decrypt later.
#
# The risk score is out of 100:
#
#     risk = 40 x gap  +  25 x weakness  +  20 x exposure  +  15 x impact
#
#     gap       how far past Mosca's deadline, scaled 0 to 1
#     weakness  how badly a quantum computer breaks the algorithm, 0 to 1
#     exposure  can the traffic actually be copied? 0 to 1
#     impact    how much the data and the system matter, 0 to 1

from crypto_rules import get_crypto_risk

# ---------------------------------------------------------------
# The assumption nobody knows. Change it here and every page follows.
# ---------------------------------------------------------------
QUANTUM_HORIZON = 10          # years from now until RSA and ECC can be broken

SCENARIOS = [
    ("Optimistic", 15),
    ("Central", 10),
    ("Pessimistic", 7),
]

GAP_CAP = 40                  # years past the deadline counted as the worst case

WEIGHTS = {"gap": 40, "weakness": 25, "exposure": 20, "impact": 15}

EXPOSURE_SCALE = {
    "Public internet": 1.0,
    "Partner / vendor network": 0.7,
    "Internal LAN": 0.4,
    "Air-gapped": 0.1,
}

SENSITIVITY_SCALE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
CRITICALITY_SCALE = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}

# Kept so older CSV files that only give a band still import.
LIFETIME_SCALE = {
    "Less than 1 year": 1,
    "1-5 years": 2,
    "5-10 years": 3,
    "More than 10 years": 4,
}
LIFETIME_YEARS = {
    "Less than 1 year": 1, "1-5 years": 5,
    "5-10 years": 10, "More than 10 years": 25,
}

LEVELS = [(75, "Critical"), (55, "High"), (35, "Medium"), (0, "Low")]


def lifetime_band(years):
    """Turn a number of years back into the familiar band."""
    if years < 1:
        return "Less than 1 year"
    if years <= 5:
        return "1-5 years"
    if years <= 10:
        return "5-10 years"
    return "More than 10 years"


def classify(score):
    for floor, name in LEVELS:
        if score >= floor:
            return name
    return "Low"


# ---------------------------------------------------------------
# Sensible defaults, so a system entered with only the basics - or
# imported from an old spreadsheet - can still be scored.
# ---------------------------------------------------------------

LONG_LIVED_50 = ("land", "deed", "registry", "encumbrance", "birth", "death",
                 "identity", "fingerprint", "case", "court", "judiciary",
                 "mining", "lease", "pension", "provident", "cabinet",
                 "prison", "certificate authority", "signing")
LONG_LIVED_40 = ("patient", "hospital", "blood", "vaccination", "medical",
                 "beneficiary", "examination", "personnel", "police")

PUBLIC_WORDS = ("portal", "website", "gateway", "booking", "wifi",
                "publisher", "press", "notice", "ticketing", "online",
                "collection", "payment", "e-")

MIGRATION_BY_TYPE = {"Database": 3, "Storage": 2, "Application": 2,
                     "Web Server": 1, "Network": 1.5, "Email": 1, "Other": 2}


def default_secrecy_years(system):
    band = system.get("lifetime")
    years = LIFETIME_YEARS.get(band, 5)
    if band == "More than 10 years":
        text = (system.get("name", "") + " " + system.get("department", "")).lower()
        if any(w in text for w in LONG_LIVED_50):
            return 50
        if any(w in text for w in LONG_LIVED_40):
            return 40
    return years


def default_exposure(system):
    name = system.get("name", "").lower()
    stype = system.get("type", "")
    if "certificate authority" in name or "vault" in name:
        return "Air-gapped"
    if stype in ("Web Server", "Network", "Email"):
        return "Public internet"
    if any(w in name for w in PUBLIC_WORDS):
        return "Public internet"
    if stype == "Application":
        return "Partner / vendor network"
    return "Internal LAN"


def default_migration_years(system):
    years = MIGRATION_BY_TYPE.get(system.get("type", ""), 2)
    crypto = get_crypto_risk(system.get("algorithm", ""), system.get("key_size"))
    if crypto["broken_now"]:
        years += 1          # legacy systems are harder to move
    return years


def fill_defaults(system):
    """Add any missing Mosca fields. Returns a new dictionary."""
    s = dict(system)
    if s.get("secrecy_years") in (None, ""):
        s["secrecy_years"] = default_secrecy_years(s)
    if s.get("migration_years") in (None, ""):
        s["migration_years"] = default_migration_years(s)
    if s.get("exposure") not in EXPOSURE_SCALE:
        s["exposure"] = default_exposure(s)
    s["secrecy_years"] = float(s["secrecy_years"])
    s["migration_years"] = float(s["migration_years"])
    s["lifetime"] = lifetime_band(s["secrecy_years"])
    return s


# ---------------------------------------------------------------
# Mosca and the score
# ---------------------------------------------------------------

def mosca(secrecy_years, migration_years, crypto, horizon=None):
    """
    Returns (gap_years, deadline_years).

    deadline_years is Z for this algorithm:
      broken today      -> 0, the deadline has already passed
      quantum-vulnerable -> the quantum horizon
      quantum-safe      -> None, no known deadline
    """
    horizon = QUANTUM_HORIZON if horizon is None else horizon
    if not crypto["vulnerable"]:
        return None, None
    deadline = 0 if crypto["broken_now"] else horizon
    return secrecy_years + migration_years - deadline, deadline


def calculate_risk(system, horizon=None):
    """Score one system. Returns the fields plus everything worked out."""
    s = fill_defaults(system)

    sens = SENSITIVITY_SCALE.get(s.get("sensitivity"))
    crit = CRITICALITY_SCALE.get(s.get("criticality"))
    if sens is None or crit is None:
        return {"name": s.get("name", "unnamed"),
                "error": "Sensitivity or criticality was not recognised."}

    crypto = get_crypto_risk(s["algorithm"], s["key_size"])
    gap_years, deadline = mosca(s["secrecy_years"], s["migration_years"],
                                crypto, horizon)

    gap_factor = 0.0
    if gap_years is not None and gap_years > 0:
        gap_factor = min(1.0, gap_years / GAP_CAP)

    weakness = crypto["weakness"]
    exposure = EXPOSURE_SCALE[s["exposure"]]
    impact = (sens / 4.0 + crit / 4.0) / 2.0

    parts = {
        "gap": WEIGHTS["gap"] * gap_factor,
        "weakness": WEIGHTS["weakness"] * weakness,
        "exposure": WEIGHTS["exposure"] * exposure,
        "impact": WEIGHTS["impact"] * impact,
    }
    score = sum(parts.values())

    if gap_years is None:
        mosca_state = "safe"
    elif gap_years > 0:
        mosca_state = "late"
    else:
        mosca_state = "inside"

    out = dict(s)
    out.update({
        "crypto_note": crypto["note"],
        "crypto_status": crypto["status"],
        "crypto_status_label": crypto["status_label"],
        "crypto_family": crypto["family"],
        "crypto_primitive": crypto["primitive"],
        "nist_level": crypto["nist_level"],
        "quantum_vulnerable": crypto["vulnerable"],
        "broken_now": crypto["broken_now"],
        "review_needed": crypto["review_needed"],

        "horizon": QUANTUM_HORIZON if horizon is None else horizon,
        "deadline_years": deadline,
        "gap_years": None if gap_years is None else round(gap_years, 1),
        "mosca_state": mosca_state,

        "gap_factor": round(gap_factor, 3),
        "weakness_factor": round(weakness, 3),
        "exposure_factor": exposure,
        "impact_factor": round(impact, 3),
        "parts": {k: round(v, 1) for k, v in parts.items()},

        # kept for the protection advice
        "sensitivity_score": sens,
        "criticality_score": crit,
        "lifetime_score": LIFETIME_SCALE[s["lifetime"]],

        "risk_score": round(score, 1),
        "risk_percentage": round(score, 1),
        "risk_level": classify(score),
        "error": None,
    })
    return out


if __name__ == "__main__":
    tests = [
        {"name": "Land Registry", "department": "Revenue", "type": "Database",
         "algorithm": "RSA", "key_size": 2048, "sensitivity": "Critical",
         "secrecy_years": 50, "migration_years": 3,
         "exposure": "Internal LAN", "criticality": "Critical"},
        {"name": "Same registry, RSA-4096", "department": "Revenue", "type": "Database",
         "algorithm": "RSA", "key_size": 4096, "sensitivity": "Critical",
         "secrecy_years": 50, "migration_years": 3,
         "exposure": "Internal LAN", "criticality": "Critical"},
        {"name": "Same registry, ML-KEM-768", "department": "Revenue", "type": "Database",
         "algorithm": "ML-KEM", "key_size": 768, "sensitivity": "Critical",
         "secrecy_years": 50, "migration_years": 3,
         "exposure": "Internal LAN", "criticality": "Critical"},
        {"name": "Payment Gateway", "department": "Finance", "type": "Application",
         "algorithm": "ECC", "key_size": 256, "sensitivity": "Critical",
         "secrecy_years": 5, "migration_years": 2,
         "exposure": "Public internet", "criticality": "Critical"},
        {"name": "Ration Cards", "department": "Civil Supplies", "type": "Database",
         "algorithm": "3DES", "key_size": 168, "sensitivity": "High",
         "lifetime": "5-10 years", "criticality": "High"},
        {"name": "Tourism Website", "department": "Tourism", "type": "Web Server",
         "algorithm": "X25519-MLKEM", "key_size": 768, "sensitivity": "Low",
         "lifetime": "Less than 1 year", "criticality": "Low"},
    ]

    print("Quantum horizon: %d years" % QUANTUM_HORIZON)
    print("")
    print("%-26s %-17s %9s %6s  %s" % ("SYSTEM", "CRYPTO", "MOSCA", "RISK", "LEVEL"))
    print("-" * 74)
    for t in tests:
        r = calculate_risk(t)
        gap = ("safe" if r["gap_years"] is None else
               ("%+.1f yr" % r["gap_years"]))
        print("%-26s %-17s %9s %6.1f  %s" % (
            r["name"][:26], "%s-%s" % (r["algorithm"], r["key_size"]),
            gap, r["risk_score"], r["risk_level"]))
