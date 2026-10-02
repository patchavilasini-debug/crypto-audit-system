# cbom.py
# Cryptographic Bill of Materials, in CycloneDX 1.6 format.
#
# UC-027 asks for the inventory to be written in a form a machine can
# re-check next quarter, not just a table a person reads once. CycloneDX
# 1.6 added a "cryptographic-asset" component type for exactly this.
#
# One component per system in the register, plus one per scanned
# certificate. Each carries its algorithm, its NIST quantum security level
# (0 means a quantum computer breaks it), and the audit's own findings
# as properties.

import datetime
import uuid

from crypto_rules import normalise

PRIMITIVE_OID = {
    "RSA": "1.2.840.113549.1.1.1",
    "ECC": "1.2.840.10045.2.1",
    "DH": "1.2.840.10046.2.1",
    "AES": "2.16.840.1.101.3.4.1",
    "SHA-256": "2.16.840.1.101.3.4.2.1",
    "SHA-384": "2.16.840.1.101.3.4.2.2",
    "SHA-1": "1.3.14.3.2.26",
    "MD5": "1.2.840.113549.2.5",
    "3DES": "1.2.840.113549.3.7",
    "ML-KEM": "2.16.840.1.101.3.4.4",
    "ML-DSA": "2.16.840.1.101.3.4.3",
    "SLH-DSA": "2.16.840.1.101.3.4.3",
}

FUNCTIONS = {
    "pke": ["encrypt", "decrypt"],
    "signature": ["sign", "verify"],
    "key-agree": ["keygen"],
    "kem": ["encapsulate", "decapsulate"],
    "block-cipher": ["encrypt", "decrypt"],
    "stream-cipher": ["encrypt", "decrypt"],
    "hash": ["digest"],
}


DATE_FORMATS = ["%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y", "%b %d %Y", "%Y-%m-%d"]


def iso_date(text):
    """Certificate dates arrive as 'Nov  5 19:59:23 2026 GMT'. CycloneDX
       requires ISO-8601. Returns None if the date cannot be read, so an
       invalid value is never written."""
    if not text:
        return None
    cleaned = " ".join(str(text).split())
    for fmt in DATE_FORMATS:
        try:
            return (datetime.datetime.strptime(cleaned, fmt)
                    .strftime("%Y-%m-%dT%H:%M:%SZ"))
        except ValueError:
            continue
    return None


def _prop(name, value):
    return {"name": "uc027:" + name, "value": "" if value is None else str(value)}


def system_component(r):
    name = normalise(r["algorithm"])
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": "system-%s" % r.get("id", r["priority"]),
        "name": "%s-%s" % (name, r["key_size"]),
        "description": "Used by %s (%s)" % (r["name"], r.get("department", "")),
        "cryptoProperties": {
            "assetType": "algorithm",
            "algorithmProperties": {
                "primitive": r.get("crypto_primitive", "unknown"),
                "parameterSetIdentifier": str(r["key_size"]),
                "cryptoFunctions": FUNCTIONS.get(r.get("crypto_primitive"), ["unknown"]),
                "nistQuantumSecurityLevel": r["nist_level"] if r["nist_level"] is not None else 0,
            },
        },
        "properties": [
            _prop("system", r["name"]),
            _prop("department", r.get("department")),
            _prop("systemType", r.get("type")),
            _prop("quantumStatus", r.get("crypto_status_label")),
            _prop("quantumVulnerable", str(bool(r["quantum_vulnerable"])).lower()),
            _prop("brokenToday", str(bool(r["broken_now"])).lower()),
            _prop("secrecyYears", r["secrecy_years"]),
            _prop("migrationYears", r["migration_years"]),
            _prop("exposure", r["exposure"]),
            _prop("moscaGapYears", r["gap_years"]),
            _prop("riskScore", r["risk_score"]),
            _prop("riskLevel", r["risk_level"]),
            _prop("migrationPriority", r["priority"]),
            _prop("recommendedReplacement", r["replacement"]),
        ],
    }
    if name in PRIMITIVE_OID:
        comp["cryptoProperties"]["oid"] = PRIMITIVE_OID[name]
    return comp


def certificate_component(scan):
    comp = {
        "type": "cryptographic-asset",
        "bom-ref": "certificate-%s" % scan["host"],
        "name": "Certificate for %s" % scan["host"],
        "cryptoProperties": {
            "assetType": "certificate",
            "certificateProperties": {
                "subjectName": scan.get("subject") or "unknown",
                "issuerName": scan.get("issuer") or "unknown",
            },
        },
        "properties": [
            _prop("host", scan["host"]),
            _prop("publicKey", "%s-%s" % (scan.get("algorithm"), scan.get("key_size"))),
            _prop("scannedAt", scan.get("scanned_at")),
            _prop("tlsVersion", scan.get("tls_version")),
            _prop("daysLeft", scan.get("days_left")),
            _prop("lifetimeDays", scan.get("lifetime_days")),
            _prop("measured", "true"),
        ],
    }
    props = comp["cryptoProperties"]["certificateProperties"]
    after = iso_date(scan.get("expires"))
    before = iso_date(scan.get("not_before"))
    if after:
        props["notValidAfter"] = after
    if before:
        props["notValidBefore"] = before
    return comp


def build_cbom(results, scans=None):
    components = [system_component(r) for r in results]
    for s in scans or []:
        if not s.get("error"):
            components.append(certificate_component(s))

    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": "urn:uuid:%s" % uuid.uuid4(),
        "version": 1,
        "metadata": {
            "timestamp": datetime.datetime.now(datetime.timezone.utc)
                         .strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tools": {"components": [{"type": "application",
                                      "name": "Crypto Audit System (UC-027)"}]},
            "component": {"type": "application", "name": "Organisation estate",
                          "bom-ref": "estate"},
        },
        "components": components,
    }


if __name__ == "__main__":
    import json
    from recommendation_engine import audit_all, SAMPLE_SYSTEMS
    bom = build_cbom(audit_all(SAMPLE_SYSTEMS))
    print("components:", len(bom["components"]))
    print(json.dumps(bom["components"][0], indent=2)[:900])
