# crypto_rules.py
# The cryptographic knowledge base.
#
# This is the ONLY file that knows anything about algorithms. Everything
# else asks this file. To update the rules, edit here and nothing else
# changes.
#
# UC-027 is about harvest-now-decrypt-later, so the question this file
# answers is not "is this algorithm strong today?" but "will a quantum
# computer be able to read what it protects?"
#
#   Shor's algorithm   breaks RSA, ECC and Diffie-Hellman completely,
#                      at ANY key size. RSA-4096 is no safer than RSA-2048.
#   Grover's algorithm roughly halves the strength of symmetric ciphers
#                      and hashes. AES-128 drops to about 64 bits of
#                      security; AES-256 still has about 128, which is fine.
#   Post-quantum       ML-KEM (FIPS 203), ML-DSA (FIPS 204) and SLH-DSA
#                      (FIPS 205) were designed to resist both.
#
# weakness runs 0 (safe against a quantum computer) to 1 (fully broken).

CRYPTO_RULES = {
    # --- broken by Shor: the heart of the harvest-now-decrypt-later risk ---
    "RSA": {
        "family": "asymmetric", "primitive": "pke", "status": "shor",
        "weakness": 1.0, "classical_min": 2048, "deprecated": False,
        "note": "Broken by Shor's algorithm on a quantum computer, at any key size.",
    },
    "ECC": {
        "family": "asymmetric", "primitive": "signature", "status": "shor",
        "weakness": 1.0, "classical_min": 256, "deprecated": False,
        "note": "Broken by Shor's algorithm. Smaller keys than RSA, same quantum fate.",
    },
    "DH": {
        "family": "key exchange", "primitive": "key-agree", "status": "shor",
        "weakness": 1.0, "classical_min": 2048, "deprecated": False,
        "note": "Broken by Shor's algorithm. Recorded key exchanges can be replayed and read later.",
    },

    # --- weakened by Grover: fixed by a bigger key, not a new algorithm ---
    "AES": {
        "family": "symmetric", "primitive": "block-cipher", "status": "grover",
        "weakness": None, "classical_min": 128, "deprecated": False,
        "note": "Grover's algorithm halves its strength, so key size decides the outcome.",
    },
    "SHA-256": {
        "family": "hash", "primitive": "hash", "status": "grover",
        "weakness": 0.25, "classical_min": 256, "deprecated": False,
        "note": "Weakened by Grover but still acceptable. Prefer SHA-384 for data kept past 2035.",
    },
    "SHA-384": {
        "family": "hash", "primitive": "hash", "status": "safe",
        "weakness": 0.05, "classical_min": 384, "deprecated": False,
        "note": "Enough margin to stay safe against a quantum computer.",
    },

    # --- broken today, no quantum computer needed ---
    "3DES": {
        "family": "symmetric", "primitive": "block-cipher", "status": "broken",
        "weakness": 1.0, "classical_min": None, "deprecated": True,
        "note": "Formally deprecated. Already breakable today, quantum or not.",
    },
    "DES": {
        "family": "symmetric", "primitive": "block-cipher", "status": "broken",
        "weakness": 1.0, "classical_min": None, "deprecated": True,
        "note": "Broken decades ago. Must not be in use.",
    },
    "RC4": {
        "family": "stream cipher", "primitive": "stream-cipher", "status": "broken",
        "weakness": 1.0, "classical_min": None, "deprecated": True,
        "note": "Prohibited in TLS since 2015.",
    },
    "SHA-1": {
        "family": "hash", "primitive": "hash", "status": "broken",
        "weakness": 1.0, "classical_min": None, "deprecated": True,
        "note": "Collisions demonstrated in 2017. Signatures made with it can be forged.",
    },
    "MD5": {
        "family": "hash", "primitive": "hash", "status": "broken",
        "weakness": 1.0, "classical_min": None, "deprecated": True,
        "note": "Trivially broken. Do not use.",
    },

    # --- post-quantum: the migration targets ---
    "ML-KEM": {
        "family": "post-quantum", "primitive": "kem", "status": "pqc",
        "weakness": 0.0, "classical_min": 512, "deprecated": False,
        "params": [512, 768, 1024],
        "note": "Post-quantum key exchange, NIST FIPS 203.",
    },
    "ML-DSA": {
        "family": "post-quantum", "primitive": "signature", "status": "pqc",
        "weakness": 0.0, "classical_min": 44, "deprecated": False,
        "params": [44, 65, 87],
        "note": "Post-quantum signatures, NIST FIPS 204.",
    },
    "SLH-DSA": {
        "family": "post-quantum", "primitive": "signature", "status": "pqc",
        "weakness": 0.0, "classical_min": 128, "deprecated": False,
        "params": [128, 192, 256],
        "note": "Hash-based post-quantum signatures, NIST FIPS 205. Slow but very conservative.",
    },
    "X25519-MLKEM": {
        "family": "post-quantum", "primitive": "kem", "status": "pqc",
        "weakness": 0.0, "classical_min": 768, "deprecated": False,
        "params": [768],
        "note": "Hybrid key exchange: classical X25519 plus ML-KEM-768. Safe if either half holds. Already in browsers.",
    },
}

# Different ways people write the same algorithm.
ALIASES = {
    "ECDSA": "ECC", "ECDH": "ECC", "EC": "ECC", "ECDHE": "ECC", "X25519": "ECC",
    "ED25519": "ECC", "P-256": "ECC",
    "DIFFIE-HELLMAN": "DH", "DHE": "DH",
    "TRIPLEDES": "3DES", "TRIPLE-DES": "3DES", "DES3": "3DES",
    "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA-2": "SHA-256", "SHA384": "SHA-384",
    "KYBER": "ML-KEM", "MLKEM": "ML-KEM", "FIPS-203": "ML-KEM",
    "DILITHIUM": "ML-DSA", "MLDSA": "ML-DSA", "FIPS-204": "ML-DSA",
    "SPHINCS+": "SLH-DSA", "SLHDSA": "SLH-DSA",
    "X25519MLKEM768": "X25519-MLKEM", "HYBRID": "X25519-MLKEM",
}

STATUS_LABEL = {
    "shor":   "Broken by a quantum computer (Shor)",
    "grover": "Weakened by a quantum computer (Grover)",
    "broken": "Broken today",
    "safe":   "Quantum-safe",
    "pqc":    "Post-quantum",
    "unknown": "Not recognised",
}

# NIST post-quantum security category, used in the CBOM export.
# 0 means a quantum computer breaks it.
NIST_LEVEL = {
    ("AES", 128): 1, ("AES", 192): 3, ("AES", 256): 5,
    ("SHA-256", None): 2, ("SHA-384", None): 4,
    ("ML-KEM", 512): 1, ("ML-KEM", 768): 3, ("ML-KEM", 1024): 5,
    ("ML-DSA", 44): 2, ("ML-DSA", 65): 3, ("ML-DSA", 87): 5,
    ("SLH-DSA", 128): 1, ("SLH-DSA", 192): 3, ("SLH-DSA", 256): 5,
    ("X25519-MLKEM", 768): 3,
}

# Anything scoring at or above this is treated as readable by a future
# quantum computer, so Mosca's deadline applies to it.
QUANTUM_VULNERABLE_AT = 0.4

UNKNOWN_WEAKNESS = 0.75


def normalise(algorithm):
    name = str(algorithm).strip().upper()
    return ALIASES.get(name, name)


def aes_weakness(size):
    if size >= 256:
        return 0.05
    if size >= 192:
        return 0.2
    if size >= 128:
        return 0.4
    return 1.0


def get_crypto_risk(algorithm, key_size):
    """
    Everything the audit needs to know about one algorithm and key size.

    Returns a dictionary with:
      weakness     0 (quantum-safe) to 1 (fully broken)
      status       shor / grover / broken / safe / pqc / unknown
      vulnerable   True if a future quantum computer reads what it protects
      broken_now   True if it is breakable today, no quantum computer needed
      review_needed, note, nist_level, family, primitive
    """
    name = normalise(algorithm)

    if name not in CRYPTO_RULES:
        return {
            "algorithm": algorithm, "family": "unknown", "primitive": "unknown",
            "status": "unknown", "status_label": STATUS_LABEL["unknown"],
            "weakness": UNKNOWN_WEAKNESS, "vulnerable": True, "broken_now": False,
            "review_needed": True, "nist_level": None,
            "note": "Not in the knowledge base. Assumed weak until a person confirms it.",
        }

    rule = CRYPTO_RULES[name]
    try:
        size = int(key_size)
    except (TypeError, ValueError):
        size = None

    note = rule["note"]
    weakness = rule["weakness"]
    status = rule["status"]
    broken_now = rule["deprecated"]

    if name == "AES":
        if size is None:
            weakness = UNKNOWN_WEAKNESS
        else:
            weakness = aes_weakness(size)
            if size >= 256:
                status = "safe"
                note = "AES-256 keeps about 128 bits of security against Grover. Quantum-safe."
            elif size < 128:
                broken_now = True
                note = "Key size %d is below 128 bits. Breakable today." % size
            else:
                note = ("AES-%d drops to about %d bits against Grover. "
                        "Move to AES-256." % (size, size // 2))

    # Classical problems on top of the quantum ones.
    elif (rule["status"] == "shor" and size is not None
          and rule["classical_min"] and size < rule["classical_min"]):
        broken_now = True
        note += (" Key size %d is also below %d, so it is weak even today."
                 % (size, rule["classical_min"]))

    elif rule.get("params") and size is not None and size not in rule["params"]:
        note += " %d is not a standard parameter set (%s)." % (
            size, ", ".join(str(p) for p in rule["params"]))

    if broken_now:
        status = "broken"
        weakness = 1.0

    level = NIST_LEVEL.get((name, size), NIST_LEVEL.get((name, None)))
    if status in ("shor", "broken"):
        level = 0

    return {
        "algorithm": name,
        "family": rule["family"],
        "primitive": rule["primitive"],
        "status": status,
        "status_label": STATUS_LABEL[status],
        "weakness": weakness,
        "vulnerable": weakness >= QUANTUM_VULNERABLE_AT,
        "broken_now": broken_now,
        "review_needed": size is None,
        "nist_level": level,
        "note": note,
    }


if __name__ == "__main__":
    tests = [("RSA", 2048), ("RSA", 4096), ("RSA", 1024), ("ECC", 256),
             ("DH", 2048), ("AES", 128), ("AES", 256), ("AES", 64),
             ("SHA-256", 256), ("SHA-1", 160), ("3DES", 168),
             ("ML-KEM", 768), ("ML-DSA", 65), ("X25519-MLKEM", 768),
             ("Kyber", 768), ("Blowfish", 448)]

    print("%-13s %-5s %-5s %-5s %s" % ("ALGORITHM", "KEY", "WEAK", "VULN", "STATUS"))
    print("-" * 70)
    for algo, size in tests:
        r = get_crypto_risk(algo, size)
        print("%-13s %-5s %-5.2f %-5s %s" % (algo, size, r["weakness"],
              "yes" if r["vulnerable"] else "no", r["status_label"]))
