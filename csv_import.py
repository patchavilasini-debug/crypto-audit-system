# csv_import.py
# Read systems from a CSV file so an organisation can hand over a
# spreadsheet instead of typing everything in one row at a time.

import csv
import io

from crypto_rules import CRYPTO_RULES, normalise
from risk_engine import (SENSITIVITY_SCALE, LIFETIME_SCALE, CRITICALITY_SCALE,
                         EXPOSURE_SCALE)

REQUIRED = ["name", "department", "type", "algorithm", "key_size",
            "sensitivity", "criticality"]

# Mosca's X. Either the number of years, or the older band name.
SECRECY_COLUMNS = ["secrecy_years", "lifetime"]

# Optional. Filled with sensible defaults if left out.
OPTIONAL = ["migration_years", "exposure"]

TEMPLATE = ("name,department,type,algorithm,key_size,sensitivity,criticality,"
            "secrecy_years,migration_years,exposure\n"
            "Land Registry,Revenue,Database,RSA,2048,Critical,Critical,50,3,Internal LAN\n"
            "Staff Payroll,Finance,Application,AES,256,Medium,Medium,7,2,Internal LAN\n"
            "Citizen Portal,IT & E-Gov,Web Server,X25519-MLKEM,768,High,High,10,1,Public internet\n")


def parse_csv(text):
    """
    Read CSV text and return (good_rows, problems).

    A bad row is reported by line number and skipped. The rest still
    load, because a real spreadsheet of two hundred systems will have
    a few typos and dying on row forty is useless.
    """
    good = []
    problems = []

    reader = csv.DictReader(io.StringIO(text))

    if reader.fieldnames is None:
        return [], ["The file appears to be empty."]

    headers = [h.strip().lower() for h in reader.fieldnames]
    missing = [c for c in REQUIRED if c not in headers]
    if not any(c in headers for c in SECRECY_COLUMNS):
        missing.append("secrecy_years (or lifetime)")
    if missing:
        return [], ["Missing column(s): " + ", ".join(missing)
                    + ". Download the template to see the expected format."]

    for line_no, raw in enumerate(reader, start=2):
        row = {}
        for k, v in raw.items():
            if k is not None:
                row[k.strip().lower()] = (v or "").strip()

        name = row.get("name", "")
        if not name:
            problems.append("Line %d: no system name." % line_no)
            continue

        # Accept common spellings: Kyber, ECDSA, SHA1 and so on.
        algorithm = normalise(row.get("algorithm", ""))
        if algorithm not in CRYPTO_RULES:
            problems.append("Line %d (%s): '%s' is not a known algorithm."
                            % (line_no, name, algorithm))
            continue

        try:
            key_size = int(row.get("key_size", ""))
            if key_size < 1 or key_size > 100000:
                raise ValueError
        except ValueError:
            problems.append("Line %d (%s): key size '%s' is not a valid number."
                            % (line_no, name, row.get("key_size", "")))
            continue

        if row.get("sensitivity") not in SENSITIVITY_SCALE:
            problems.append("Line %d (%s): sensitivity '%s' is not recognised."
                            % (line_no, name, row.get("sensitivity", "")))
            continue

        secrecy = None
        if row.get("secrecy_years"):
            try:
                secrecy = float(row["secrecy_years"])
                if secrecy < 0 or secrecy > 200:
                    raise ValueError
            except ValueError:
                problems.append("Line %d (%s): secrecy_years '%s' is not a number from 0 to 200."
                                % (line_no, name, row["secrecy_years"]))
                continue
        elif row.get("lifetime") not in LIFETIME_SCALE:
            problems.append("Line %d (%s): give secrecy_years (a number), or lifetime "
                            "as one of: Less than 1 year, 1-5 years, 5-10 years, "
                            "More than 10 years." % (line_no, name))
            continue

        migration = None
        if row.get("migration_years"):
            try:
                migration = float(row["migration_years"])
                if migration < 0 or migration > 20:
                    raise ValueError
            except ValueError:
                problems.append("Line %d (%s): migration_years '%s' is not a number from 0 to 20."
                                % (line_no, name, row["migration_years"]))
                continue

        exposure = row.get("exposure") or None
        if exposure and exposure not in EXPOSURE_SCALE:
            problems.append("Line %d (%s): exposure '%s' is not recognised."
                            % (line_no, name, exposure))
            continue

        if row.get("criticality") not in CRITICALITY_SCALE:
            problems.append("Line %d (%s): criticality '%s' is not recognised."
                            % (line_no, name, row.get("criticality", "")))
            continue

        good.append({
            "name": name[:80],
            "department": row.get("department") or "Unassigned",
            "type": row.get("type") or "Other",
            "algorithm": algorithm,
            "key_size": key_size,
            "sensitivity": row["sensitivity"],
            "lifetime": row.get("lifetime") or None,
            "secrecy_years": secrecy,
            "migration_years": migration,
            "exposure": exposure,
            "criticality": row["criticality"],
        })

    return good, problems


if __name__ == "__main__":
    test = (TEMPLATE
            + "Broken One,Home,Database,Blowfish,448,High,1-5 years,High\n"
            + "Bad Key,Home,Database,RSA,abc,High,1-5 years,High\n"
            + ",Home,Database,RSA,2048,High,1-5 years,High\n"
            + "Bad Level,Home,Database,RSA,2048,Very High,1-5 years,High\n")

    good, problems = parse_csv(test)
    print("Loaded %d row(s):" % len(good))
    for g in good:
        print("   " + g["name"] + " (" + g["department"] + ")")
    print("")
    print("Skipped %d row(s):" % len(problems))
    for p in problems:
        print("   " + p)
