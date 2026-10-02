# code_scan.py
# Finds old cryptography inside source code.
#
# The audit pages cover systems you can see from outside. This covers the
# part you cannot: algorithm names written into programs. UC-027 asks for
# "hardcoded crypto in source repos", and this is it.
#
# Nothing is stored. The uploaded code is read in memory and thrown away.

import io
import os
import re
import zipfile

# What we look for. Each entry: pattern, what it is, how bad, what to use.
#   broken   - breakable today, no quantum computer needed
#   quantum  - a quantum computer breaks it
#   weak     - not broken, but below what is recommended
RULES = [
    (r"\bmd5\b",                      "MD5",            "broken",  "SHA-384"),
    (r"\bsha[-_ ]?1\b",               "SHA-1",          "broken",  "SHA-384"),
    (r"\bmd4\b",                      "MD4",            "broken",  "SHA-384"),
    (r"\b3des\b|\btriple[-_ ]?des\b|\bdes[-_ ]?ede\d?\b|\bdes3\b",
                                      "3DES",           "broken",  "AES-256-GCM"),
    (r"\bdes\b(?![a-z])",             "DES",            "broken",  "AES-256-GCM"),
    (r"\brc4\b|\barcfour\b",          "RC4",            "broken",  "AES-256-GCM"),
    (r"\brc2\b",                      "RC2",            "broken",  "AES-256-GCM"),
    (r"\bblowfish\b",                 "Blowfish",       "broken",  "AES-256-GCM"),
    (r"\bsslv?[-_ ]?[23]\b|\btlsv?[-_ ]?1[._][01]\b",
                                      "Old TLS",        "broken",  "TLS 1.3"),
    (r"\brsa\b",                      "RSA",            "quantum", "ML-KEM + ML-DSA"),
    (r"\becdsa\b|\becdhe?\b|\bed25519\b|\bx25519\b|secp256|prime256v1|\bnistp256\b",
                                      "Elliptic curve", "quantum", "ML-KEM + ML-DSA"),
    (r"\bdiffie|\bdhe?\b(?=[^a-z])",  "Diffie-Hellman", "quantum", "ML-KEM"),
    (r"aes[-_ ]?128|\baes\b.{0,12}\b128\b",
                                      "AES-128",        "weak",    "AES-256"),
    (r"\bsha[-_ ]?256\b",             "SHA-256",        "weak",    "SHA-384 if kept past 2035"),
]

COMPILED = [(re.compile(p, re.I), name, status, fix) for p, name, status, fix in RULES]

STATUS_TEXT = {
    "broken":  "Broken today",
    "quantum": "Quantum breaks it",
    "weak":    "Below recommended",
}

CODE_TYPES = {".py", ".js", ".ts", ".java", ".cs", ".php", ".go", ".rb", ".c",
              ".cpp", ".h", ".swift", ".kt", ".sql", ".sh", ".ps1", ".pl",
              ".json", ".xml", ".yml", ".yaml", ".conf", ".ini", ".properties",
              ".env", ".txt", ".md", ".tf", ".gradle"}

SKIP_DIRS = ("node_modules/", "venv/", ".git/", "__pycache__/", "dist/", "build/")

MAX_FILE = 2 * 1024 * 1024        # 2 MB per file
MAX_FILES = 300
MAX_FINDINGS = 500


def looks_like_code(name):
    return os.path.splitext(name)[1].lower() in CODE_TYPES


def skip(name):
    flat = name.replace("\\", "/")
    return any(d in flat for d in SKIP_DIRS)


def scan_text(name, text):
    """Every weak algorithm used in one file."""
    out = []
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > 400:
            continue
        seen = set()
        for pattern, algo, status, fix in COMPILED:
            if algo in seen or not pattern.search(line):
                continue
            seen.add(algo)
            out.append({"file": name, "line": number, "code": line.strip()[:120],
                        "algorithm": algo, "status": status,
                        "status_text": STATUS_TEXT[status], "fix": fix})
    return out


def scan_upload(filename, data):
    """
    Scan one uploaded file. A .zip is opened and every code file inside
    is scanned. Returns (findings, files_scanned, notes).
    """
    findings, scanned, notes = [], 0, []

    if filename.lower().endswith(".zip"):
        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
        except zipfile.BadZipFile:
            return [], 0, ["That zip file could not be opened."]

        for info in zf.infolist():
            if scanned >= MAX_FILES:
                notes.append("Stopped after %d files." % MAX_FILES)
                break
            if info.is_dir() or skip(info.filename) or not looks_like_code(info.filename):
                continue
            if info.file_size > MAX_FILE:
                notes.append("%s skipped, over 2 MB." % info.filename)
                continue
            try:
                text = zf.read(info).decode("utf-8", "ignore")
            except Exception:
                continue
            scanned += 1
            findings.extend(scan_text(info.filename, text))
    else:
        if len(data) > MAX_FILE:
            return [], 0, ["That file is over 2 MB."]
        if not looks_like_code(filename):
            notes.append("Not a code file type, scanned anyway.")
        scanned = 1
        findings.extend(scan_text(filename, data.decode("utf-8", "ignore")))

    if len(findings) > MAX_FINDINGS:
        notes.append("Showing the first %d results." % MAX_FINDINGS)
        findings = findings[:MAX_FINDINGS]

    order = {"broken": 0, "quantum": 1, "weak": 2}
    findings.sort(key=lambda f: (order[f["status"]], f["file"], f["line"]))
    return findings, scanned, notes


def summarise(findings):
    counts = {"broken": 0, "quantum": 0, "weak": 0}
    algos, files = {}, set()
    for f in findings:
        counts[f["status"]] += 1
        algos[f["algorithm"]] = algos.get(f["algorithm"], 0) + 1
        files.add(f["file"])
    return {"broken": counts["broken"], "quantum": counts["quantum"],
            "weak": counts["weak"], "total": len(findings),
            "files": len(files),
            "algorithms": sorted(algos.items(), key=lambda x: -x[1])}


if __name__ == "__main__":
    sample = '''
import hashlib
from Crypto.Cipher import DES3

def old_hash(pw):
    return hashlib.md5(pw).hexdigest()          # bad

def signature(data):
    return hashlib.sha1(data).digest()

cipher = DES3.new(key, DES3.MODE_CBC)
key = RSA.generate(2048)
ctx.set_ciphers("ECDHE-RSA-AES128-SHA")
checksum = hashlib.sha256(blob).hexdigest()
address = "12 Desai Road"   # the word Desai must not be flagged
'''
    findings, scanned, notes = scan_upload("legacy.py", sample.encode())
    s = summarise(findings)
    print("files %d | broken %d | quantum %d | weak %d"
          % (scanned, s["broken"], s["quantum"], s["weak"]))
    print("")
    for f in findings:
        print("  line %-3d %-15s %-18s -> %s" % (f["line"], f["algorithm"],
                                                 f["status_text"], f["fix"]))
