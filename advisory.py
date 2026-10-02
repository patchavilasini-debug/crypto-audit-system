# advisory.py
# Turns a risk score into a protection plan somebody can act on.
#
# The audit says WHAT is wrong. This says WHAT TO DO ABOUT IT.
#
# Advice is built in layers:
#   1. This week      - costs nothing, reduces exposure immediately
#   2. Replace        - the actual algorithm change
#   3. Data at rest   - the part everyone forgets
#   4. Keys           - a new algorithm with badly kept keys is no better
#   5. Verify         - prove the change took effect
#   6. Ongoing        - stop it drifting back

from crypto_rules import CRYPTO_RULES, ALIASES

# ---------------------------------------------------------------
# What to move to, per algorithm family
# ---------------------------------------------------------------

TARGETS = {
    "asymmetric": {
        "use": "Hybrid X25519 + ML-KEM-768 for key exchange; ML-DSA-65 for signatures",
        "why": "RSA and ECC are broken by a quantum computer at any key size, so a "
               "bigger key does not help. Hybrid keeps old clients working while "
               "adding post-quantum protection, and is already in current browsers.",
        "protocol": "TLS 1.3 with the X25519MLKEM768 group enabled. Disable TLS 1.0 and 1.1.",
    },
    "key exchange": {
        "use": "Hybrid X25519 + ML-KEM-768 (FIPS 203)",
        "why": "Recorded Diffie-Hellman exchanges can be replayed through a quantum "
               "computer later. This is the purest harvest-now-decrypt-later target.",
        "protocol": "TLS 1.3 negotiates the hybrid group automatically once enabled.",
    },
    "symmetric": {
        "use": "AES-256-GCM",
        "why": "Grover's algorithm halves symmetric strength, so AES-256 keeps about "
               "128 bits. That is enough. GCM also detects tampering.",
        "protocol": "Never reuse an initialisation vector with the same key.",
    },
    "hash": {
        "use": "SHA-384 for anything kept past 2035, SHA-256 otherwise",
        "why": "For passwords do not use a plain hash at all: use Argon2id or scrypt.",
        "protocol": "Re-sign anything currently signed with SHA-1 or MD5.",
    },
    "stream cipher": {
        "use": "AES-256-GCM",
        "why": "Use a block cipher in an authenticated mode instead.",
        "protocol": "Remove the old cipher from every allowed cipher list.",
    },
    "post-quantum": {
        "use": "Already post-quantum. Keep it, and keep it replaceable",
        "why": "Post-quantum standards are new. SIKE was a shortlisted candidate and "
               "was broken on a laptop in 2022, so route it through the crypto "
               "service so it can be swapped again if needed.",
        "protocol": "Prefer hybrid modes until the standards have been in service longer.",
    },
}

# ---------------------------------------------------------------
# Things to do right now, before any migration starts
# ---------------------------------------------------------------

CONTAINMENT = {
    "Critical": [
        "Stop adding new sensitive records to this system until the migration "
        "plan is signed off. Every day it runs adds to what is exposed.",
        "Take it off the public internet if it does not need to be there. "
        "Put it behind a VPN or an allow-list of known addresses.",
        "Turn on full connection logging today, so that if this system is "
        "later found to have been copied you know when and by whom.",
        "Shorten the certificate lifetime to 90 days now. It does not fix the "
        "algorithm, but it limits how long a stolen key stays useful.",
    ],
    "High": [
        "Check who can reach this system and remove anyone who does not need "
        "to. Most exposure is access nobody remembered to revoke.",
        "Turn on connection logging if it is not already running.",
        "Reduce the certificate lifetime to 90 days at the next renewal.",
    ],
    "Medium": [
        "Add this system to the migration register so it is not forgotten.",
        "Confirm backups of this system are encrypted separately.",
    ],
    "Low": [
        "No immediate action. Review the configuration at the annual audit.",
    ],
}

# ---------------------------------------------------------------
# If you genuinely cannot migrate yet
# ---------------------------------------------------------------

INTERIM = [
    "Reduce what the system holds. Data you have deleted cannot be stolen, "
    "and most systems keep far more history than the law requires.",
    "Wrap the weak channel inside a strong one. A VPN using modern "
    "cryptography around a legacy application buys real time.",
    "Segment the network so this system cannot be reached from a general "
    "office machine.",
    "Rotate the keys now and again at every certificate renewal, so that a "
    "key copied today stops being useful sooner.",
]


def family_of(algorithm):
    name = str(algorithm).strip().upper()
    name = ALIASES.get(name, name)
    rule = CRYPTO_RULES.get(name)
    return rule["family"] if rule else "unknown"


RECORD_KINDS = [
    (("patient", "hospital", "health", "imaging", "blood", "vaccination",
      "ambulance", "drug"),
     "Patient record", "patient records",
     "e.g. Patient 90214, admitted 14 March, ward B, Type 2 diabetes"),
    (("land", "property", "registry", "deed", "survey", "encumbrance",
      "stamp", "mining", "lease"),
     "Land record", "land records",
     "e.g. Deed 4417, Survey 118/2A, owner R. Kumar, 2.4 acres"),
    (("payroll", "pension", "provident", "salary", "employee", "personnel"),
     "Employee record", "employee records",
     "e.g. Employee 3312, grade 4, basic pay, account ending 4417"),
    (("case", "police", "court", "judiciary", "cctv", "prison",
      "fingerprint", "offence", "challan"),
     "Case record", "case records",
     "e.g. Case 221/2026, witness reference, charge sheet number"),
    (("identity", "birth", "death", "beneficiary", "ration", "card",
      "citizen", "member"),
     "Citizen record", "citizen records",
     "e.g. Citizen 4471, address, entitlement code, family size"),
    (("payment", "treasury", "tax", "billing", "duty", "toll", "procure",
      "budget", "donation", "royalty", "gst"),
     "Transaction record", "transaction records",
     "e.g. Voucher TR-8823, vendor 4471, amount, sanction reference"),
    (("exam", "student", "scholarship", "athlete"),
     "Student record", "student records",
     "e.g. Roll 21B451, marks, scholarship reference"),
    (("farmer", "crop", "soil", "agri", "weaver", "fishing", "boat",
      "timber", "forest"),
     "Field record", "field records",
     "e.g. Farmer 8821, survey number, subsidy claim, season"),
]


def record_kind(system):
    """
    What sort of record this system holds, so the upload box asks for
    the right thing. A page that says "paste your data" gets ignored;
    one that says "e.g. Patient 90214, ward B" gets used.
    """
    text = ((system.get("name", "") + " " + system.get("department", ""))
            .lower())
    for words, label, plural, hint in RECORD_KINDS:
        for w in words:
            if w in text:
                return {"label": label, "plural": plural, "hint": hint}
    return {"label": "Record", "plural": "records",
            "hint": "Paste the record you want to protect"}


def build_advisory(system, result):
    """
    Build the full protection plan for one scored system.
    'result' is what calculate_risk returned.
    """
    level = result["risk_level"]
    family = family_of(system["algorithm"])
    target = TARGETS.get(family)

    kind = record_kind(system)

    plan = {
        "name": system["name"],
        "kind_label": kind["label"],
        "kind_plural": kind["plural"],
        "kind_hint": kind["hint"],
        "level": level,
        "percentage": result["risk_percentage"],
        "family": family,
        "containment": CONTAINMENT.get(level, CONTAINMENT["Medium"]),
        "interim": INTERIM,
    }

    # --- 2. replace the algorithm ---
    if target:
        plan["target_use"] = target["use"]
        plan["target_why"] = target["why"]
        plan["target_protocol"] = target["protocol"]
    else:
        plan["target_use"] = "Identify what this algorithm actually is before " \
                             "deciding on a replacement."
        plan["target_why"] = "An algorithm nobody recognises is a risk in itself."
        plan["target_protocol"] = "Have a person confirm the configuration."

    # --- 3. data already stored ---
    at_rest = []
    if result["lifetime_score"] >= 3:
        at_rest.append(
            "This data must stay private for years, so changing the algorithm "
            "on new records is not enough. Everything already stored has to be "
            "decrypted with the old key and re-encrypted with the new one.")
        at_rest.append(
            "Re-encrypt in batches, oldest first, and keep a record of which "
            "batches are done. A half finished re-encryption that nobody "
            "tracked is worse than not starting.")
    else:
        at_rest.append(
            "This data has a short life, so you may not need to re-encrypt "
            "history. Confirm the retention period first, then simply let the "
            "old records expire under the old key.")
    at_rest.append(
        "Encrypt backups separately with their own key. A backup restored onto "
        "a new server is the most common way old cryptography comes back.")
    plan["at_rest"] = at_rest

    # --- 4. key management ---
    # NB: named key_care, not keys. In a template, plan.keys resolves to the
    # dictionary's own .keys() method and silently breaks.
    key_care = [
        "Keep private keys in a hardware security module or a managed key "
        "vault, never in a file on the application server.",
        "Give every system its own key. Shared keys mean one loss compromises "
        "everything at once.",
        "Write down who is allowed to use each key and review that list "
        "quarterly.",
    ]
    if system["sensitivity"] in ("Critical", "High"):
        key_care.insert(0,
            "This system holds sensitive data, so require two people to "
            "authorise any key export or recovery.")
    plan["key_care"] = key_care

    # --- 5. verify ---
    plan["verify"] = [
        "Re-run this audit after the change. The entry should move down the "
        "priority list. If it does not, the change did not take effect.",
        "Scan the live service from outside and confirm the old algorithm is "
        "actually refused, not merely deprioritised.",
        "Search the source code for the old algorithm name. Anything left is "
        "a place the migration missed.",
        "Confirm no application needed rebuilding. If one did, its "
        "cryptography is still written into its own code.",
    ]

    # --- 6. ongoing ---
    plan["ongoing"] = [
        "Add a cryptography check to the change approval process so new "
        "systems cannot arrive with old algorithms.",
        "Put a clause in vendor contracts requiring a cryptographic bill of "
        "materials at delivery and a demonstrated algorithm change.",
        "Re-run this audit every six months. Cryptography advice moves, and a "
        "system that passed last year may not pass now.",
    ]

    return plan


def general_advisory():
    """Advice that applies to any organisation, regardless of its systems."""
    return [
        {"title": "Encrypt in transit and at rest, not one or the other",
         "text": "Most organisations do one. Data moving between offices needs "
                 "TLS 1.3. Data sitting in a database needs its own encryption "
                 "with its own key. Doing only the first protects nothing once "
                 "someone has a copy of the disk."},
        {"title": "Assume the copy has already been taken",
         "text": "Encrypted traffic can be recorded today and opened years "
                 "later when the algorithm weakens. That is why data lifetime "
                 "matters as much as the algorithm: a record that must stay "
                 "private for fifty years needs cryptography that lasts fifty "
                 "years, and almost none does."},
        {"title": "Keep the algorithm in one place",
         "text": "If the algorithm name appears in forty files, changing it "
                 "takes years. If it appears in one configuration file that "
                 "every application reads, changing it takes days. This is the "
                 "single biggest thing you can do to make future migrations "
                 "cheap."},
        {"title": "Shorten certificate lifetimes",
         "text": "Three year certificates mean a three year rotation whatever "
                 "else you fix. Ninety day certificates with automated renewal "
                 "turn the whole estate over four times a year on their own."},
        {"title": "Delete what you do not need",
         "text": "The cheapest protection available. Data that has passed its "
                 "retention period and been properly deleted cannot be stolen, "
                 "cannot be decrypted later, and does not need migrating."},
        {"title": "Write down what you run",
         "text": "You cannot protect what you have not counted. A cryptographic "
                 "inventory that is kept current is worth more than any single "
                 "technical control, because every other decision depends on "
                 "it."},
    ]


if __name__ == "__main__":
    from risk_engine import calculate_risk
    from recommendation_engine import SAMPLE_SYSTEMS

    s = SAMPLE_SYSTEMS[0]
    r = calculate_risk(s)
    plan = build_advisory(s, r)

    print("=" * 72)
    print("PROTECTION ADVISORY: " + plan["name"])
    print("%s  %.1f%%  family: %s" % (plan["level"], plan["percentage"], plan["family"]))
    print("=" * 72)
    for key, title in [("containment", "1. THIS WEEK"),
                       ("at_rest", "3. DATA ALREADY STORED"),
                       ("key_care", "4. KEY MANAGEMENT"),
                       ("verify", "5. HOW TO CHECK IT WORKED"),
                       ("ongoing", "6. STOP IT COMING BACK")]:
        print("")
        print(title)
        print("-" * 72)
        for line in plan[key]:
            print("   * " + line)
    print("")
    print("2. REPLACE WITH")
    print("-" * 72)
    print("   Use      : " + plan["target_use"])
    print("   Why      : " + plan["target_why"])
    print("   Protocol : " + plan["target_protocol"])


# ---------------------------------------------------------------
# When the lock is ALREADY broken - not a future quantum problem, a
# today problem. Showing that it is broken is not enough; these are the
# things to do about it, in order.
# ---------------------------------------------------------------

def emergency_steps(r):
    """Five steps for a system whose cryptography is broken today.
       A broken seal (SHA-1, MD5) and a broken lock (3DES, RC4, small keys)
       need slightly different things."""
    seal = r.get("crypto_primitive") == "hash"
    name = "%s-%s" % (r.get("algorithm"), r.get("key_size"))

    if seal:
        return [
            ("Stop using it for new documents",
             "Switch new seals and signatures from %s to SHA-384 today. "
             "Usually a settings change." % name),
            ("Re-seal what is stored",
             "Give every stored document a new SHA-384 seal. The tool below "
             "does it without the documents leaving this computer."),
            ("Check old documents for forgery",
             "Compare important records against another copy - paper, a backup, "
             "the other party's copy. A forged one passes the old seal."),
            ("Delete what is no longer needed",
             "Records past their retention period cannot be forged if they "
             "are gone."),
            ("Tell people which seals to trust",
             "Anything sealed only with %s after today should be treated as "
             "unverified." % r.get("algorithm")),
        ]

    return [
        ("Stop using it for new data",
         "Lock new data with AES-256 from today. Often a settings change, "
         "not a rebuild."),
        ("Wrap it in a strong connection",
         "Put the system behind TLS 1.3 or a VPN, so anything copied from the "
         "network from now on is useless - even before the system is fixed."),
        ("Re-lock what is stored",
         "Open stored data with the old key and lock it again with AES-256. "
         "Exported files can be re-locked with the tool below."),
        ("Delete what is no longer needed",
         "Data that no longer exists cannot be read, whatever lock it had."),
        ("Treat old copies as exposed",
         "Anything copied before today may already be readable, and that "
         "cannot be undone. Change passwords, keys and account details inside it, "
         "and watch for misuse."),
    ]
