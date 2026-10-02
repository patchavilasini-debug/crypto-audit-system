# crypto_service.py
# The crypto-agility layer - the second half of UC-027.
#
# Every part of this application that needs cryptography asks THIS file.
# No other file names an algorithm or calls a crypto primitive. Which
# algorithm is used is decided by crypto_policy.json, not by code.
#
# The test of success, from the use case:
#   "Can we swap the algorithm next year without touching application code?"
#
# Here the answer is yes, and the Agility page proves it:
#   - change the policy, and new passwords are hashed with the new algorithm
#   - old passwords still work, and are quietly upgraded at the next sign in
#   - new signatures use the new algorithm, old ones still verify
#   - no application file changes

import base64
import hashlib
import hmac
import json
import os
import secrets

POLICY_FILE = "crypto_policy.json"
KEY_DIR = os.path.join("data", "keys")

DEFAULT_POLICY = {
    "password_hash": "pbkdf2-sha256",
    "signature": "ecdsa-p256",
    "certificate_key": "ecdsa-p256",
}

# ---------------------------------------------------------------
# What the service knows how to do. Adding an algorithm means adding an
# entry here - nothing that calls the service changes.
# ---------------------------------------------------------------

PASSWORD_ALGORITHMS = {
    "pbkdf2-sha256": {"label": "PBKDF2-SHA256, 250,000 rounds", "quantum": "Quantum-safe"},
    "pbkdf2-sha512": {"label": "PBKDF2-SHA512, 210,000 rounds", "quantum": "Quantum-safe"},
    "scrypt":        {"label": "scrypt, N=16384 r=8 p=1",       "quantum": "Quantum-safe"},
}

SIGNATURE_ALGORITHMS = {
    "rsa-pss-3072": {"label": "RSA-PSS 3072",   "quantum": "Broken by Shor",
                     "note": "Today's common choice. A quantum computer can forge it."},
    "ecdsa-p256":   {"label": "ECDSA P-256",    "quantum": "Broken by Shor",
                     "note": "Smaller and faster than RSA, same quantum fate."},
    "ed25519":      {"label": "Ed25519",        "quantum": "Broken by Shor",
                     "note": "Modern and fast, still elliptic-curve."},
}

# Post-quantum signatures plug in here. The Python cryptography library
# did not expose ML-DSA when this was written; when it does, or when
# liboqs is installed, one entry is added below and nothing else changes.
PQC_SIGNATURES_PENDING = {
    "ml-dsa-65": {"label": "ML-DSA-65 (FIPS 204)", "quantum": "Post-quantum",
                  "note": "The migration target. Needs a library that provides it."},
}

CERT_KEY_ALGORITHMS = {
    "ecdsa-p256": "ECDSA P-256",
    "ecdsa-p384": "ECDSA P-384",
    "rsa-3072":   "RSA 3072",
}


# ---------------------------------------------------------------
# The policy
# ---------------------------------------------------------------

def load_policy():
    policy = dict(DEFAULT_POLICY)
    if os.path.exists(POLICY_FILE):
        try:
            with open(POLICY_FILE, encoding="utf-8") as f:
                stored = json.load(f)
            for k in DEFAULT_POLICY:
                if k in stored:
                    policy[k] = stored[k]
        except (ValueError, OSError):
            pass
    return policy


def save_policy(policy):
    """Validate and write the policy. Returns (ok, message)."""
    clean = dict(load_policy())
    if policy.get("password_hash") not in PASSWORD_ALGORITHMS:
        return False, "Unknown password algorithm."
    if policy.get("signature") not in SIGNATURE_ALGORITHMS:
        return False, "Unknown or unavailable signature algorithm."
    if policy.get("certificate_key") not in CERT_KEY_ALGORITHMS:
        return False, "Unknown certificate key algorithm."
    for k in DEFAULT_POLICY:
        clean[k] = policy[k]
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(clean, f, indent=2)
    return True, "Policy saved."


# ---------------------------------------------------------------
# Passwords
#
# Stored as   algorithm$parameters$salt$hash
# so a stored hash always says how it was made. That is what lets the
# algorithm change without breaking anyone's existing password.
# ---------------------------------------------------------------

def _derive(algorithm, password, salt):
    pw = password.encode("utf-8")
    if algorithm == "pbkdf2-sha256":
        return "250000", hashlib.pbkdf2_hmac("sha256", pw, salt, 250000)
    if algorithm == "pbkdf2-sha512":
        return "210000", hashlib.pbkdf2_hmac("sha512", pw, salt, 210000)
    if algorithm == "scrypt":
        return "16384.8.1", hashlib.scrypt(pw, salt=salt, n=16384, r=8, p=1, dklen=32)
    raise ValueError("unknown password algorithm: %s" % algorithm)


def hash_password(password):
    algorithm = load_policy()["password_hash"]
    salt = secrets.token_bytes(16)
    params, digest = _derive(algorithm, password, salt)
    return "%s$%s$%s$%s" % (algorithm, params, salt.hex(), digest.hex())


def password_algorithm(stored, legacy_salt=None):
    if stored and "$" in stored:
        return stored.split("$", 1)[0]
    return "pbkdf2-sha256"          # the format used before this service existed


def verify_password(password, stored, legacy_salt=None):
    """True if the password matches. Understands every format ever used."""
    try:
        if stored and "$" in stored:
            algorithm, _params, salt_hex, digest_hex = stored.split("$", 3)
            _, digest = _derive(algorithm, password, bytes.fromhex(salt_hex))
            return hmac.compare_digest(digest.hex(), digest_hex)
        # Legacy: hash and salt kept in separate columns, PBKDF2-SHA256.
        if legacy_salt:
            _, digest = _derive("pbkdf2-sha256", password, bytes.fromhex(legacy_salt))
            return hmac.compare_digest(digest.hex(), stored)
    except (ValueError, TypeError):
        return False
    return False


def needs_rehash(stored):
    """True if this hash was made under an older policy."""
    return password_algorithm(stored) != load_policy()["password_hash"]


def dummy_verify(password):
    """Same amount of work as a real check, so timing does not reveal
       whether a username exists."""
    _derive(load_policy()["password_hash"], password, secrets.token_bytes(16))


# ---------------------------------------------------------------
# Signatures
# ---------------------------------------------------------------

def _crypto():
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
    return hashes, serialization, ec, ed25519, padding, rsa


def _new_private_key(algorithm):
    hashes, serialization, ec, ed25519, padding, rsa = _crypto()
    if algorithm in ("ecdsa-p256",):
        return ec.generate_private_key(ec.SECP256R1())
    if algorithm == "ecdsa-p384":
        return ec.generate_private_key(ec.SECP384R1())
    if algorithm in ("rsa-pss-3072", "rsa-3072"):
        return rsa.generate_private_key(public_exponent=65537, key_size=3072)
    if algorithm == "ed25519":
        return ed25519.Ed25519PrivateKey.generate()
    raise ValueError("unknown key algorithm: %s" % algorithm)


def _signing_key(algorithm):
    """One key per algorithm, created the first time it is needed.
       In production this would live in a hardware security module."""
    hashes, serialization, ec, ed25519, padding, rsa = _crypto()
    os.makedirs(KEY_DIR, exist_ok=True)
    path = os.path.join(KEY_DIR, algorithm + ".pem")
    if os.path.exists(path):
        with open(path, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    key = _new_private_key(algorithm)
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption()))
    return key


def _sign_with(algorithm, key, data):
    hashes, serialization, ec, ed25519, padding, rsa = _crypto()
    if algorithm.startswith("ecdsa"):
        return key.sign(data, ec.ECDSA(hashes.SHA256()))
    if algorithm.startswith("rsa-pss"):
        return key.sign(data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                          salt_length=padding.PSS.MAX_LENGTH),
                        hashes.SHA256())
    if algorithm == "ed25519":
        return key.sign(data)
    raise ValueError("unknown signature algorithm: %s" % algorithm)


def _verify_with(algorithm, public_key, data, signature):
    hashes, serialization, ec, ed25519, padding, rsa = _crypto()
    if algorithm.startswith("ecdsa"):
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    elif algorithm.startswith("rsa-pss"):
        public_key.verify(signature, data,
                          padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                      salt_length=padding.PSS.MAX_LENGTH),
                          hashes.SHA256())
    elif algorithm == "ed25519":
        public_key.verify(signature, data)
    else:
        raise ValueError("unknown signature algorithm: %s" % algorithm)


def sign(text):
    """Sign with whatever the policy says. The caller never names an algorithm.
       Returns a token:  algorithm.signature  (base64)"""
    algorithm = load_policy()["signature"]
    key = _signing_key(algorithm)
    sig = _sign_with(algorithm, key, text.encode("utf-8"))
    return "%s.%s" % (algorithm, base64.urlsafe_b64encode(sig).decode("ascii"))


def verify(text, token):
    """True if the token is a valid signature of the text. Works for tokens
       made under any earlier policy, because the token names its algorithm."""
    try:
        algorithm, sig_b64 = token.split(".", 1)
        if algorithm not in SIGNATURE_ALGORITHMS:
            return False
        key = _signing_key(algorithm)
        _verify_with(algorithm, key.public_key(), text.encode("utf-8"),
                     base64.urlsafe_b64decode(sig_b64.encode("ascii")))
        return True
    except Exception:
        return False


# ---------------------------------------------------------------
# Certificates, used by make_cert.py
# ---------------------------------------------------------------

def new_certificate_key():
    algorithm = load_policy()["certificate_key"]
    return _new_private_key(algorithm), CERT_KEY_ALGORITHMS[algorithm]


def certificate_hash():
    hashes = _crypto()[0]
    return hashes.SHA256()


# ---------------------------------------------------------------
# Measuring agility in this very codebase
# ---------------------------------------------------------------

# Direct calls to crypto primitives. Outside this file, each one is a place
# the algorithm is welded into the code.
CALL_SITE_PATTERNS = [
    "hashlib.pbkdf2_hmac(", "hashlib.scrypt(", "hashlib.sha1(", "hashlib.md5(",
    "hashlib.sha256(", "hashlib.sha512(", ".generate_private_key(",
    "Ed25519PrivateKey.generate(", "padding.PSS(", "AESGCM(", "Cipher(",
    "hashes.SHA256()", "hashes.SHA384()", "ec.SECP256R1()", "ec.SECP384R1()",
]

# Files allowed to name algorithms: this service, and the files whose job
# is to DESCRIBE algorithms rather than use them - the knowledge base, the
# network scanner, and the code scanner (which carries sample bad code as
# test data).
ALLOWED_FILES = {"crypto_service.py", "crypto_rules.py", "scanner.py",
                 "code_scan.py"}


def hardcoded_call_sites(folder="."):
    """Search every Python file for crypto used directly instead of through
       the service. The number should be zero."""
    found = []
    for name in sorted(os.listdir(folder)):
        if not name.endswith(".py") or name in ALLOWED_FILES:
            continue
        try:
            with open(os.path.join(folder, name), encoding="utf-8") as f:
                for n, line in enumerate(f, start=1):
                    code = line.split("#", 1)[0]
                    for pattern in CALL_SITE_PATTERNS:
                        if pattern in code:
                            found.append({"file": name, "line": n,
                                          "code": line.strip()[:90]})
                            break
        except OSError:
            continue
    return found


if __name__ == "__main__":
    print("Policy:", load_policy())
    h = hash_password("example-password")
    print("Stored hash starts:", h[:40] + "...")
    print("Verifies:", verify_password("example-password", h))
    t = sign("Deed 4417, Survey 118/2A, owner R. Kumar")
    print("Signature token starts:", t[:40] + "...")
    print("Signature verifies:", verify("Deed 4417, Survey 118/2A, owner R. Kumar", t))
    print("Tampered text verifies:", verify("Deed 4417, Survey 118/2A, owner X", t))
    sites = hardcoded_call_sites()
    print("Crypto call sites outside the service:", len(sites))
    for s in sites:
        print("   %s:%d  %s" % (s["file"], s["line"], s["code"]))
