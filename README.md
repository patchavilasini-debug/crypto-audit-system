# Crypto Audit System — UC-027

**Harvest-now-decrypt-later threat audit and crypto-agility.**
QAIC 100 Quantum Use Cases, Amaravati Quantum Valley, Government of Andhra Pradesh.

An adversary does not need a quantum computer today. They can copy encrypted
traffic and stored data now, keep it, and read it once a quantum computer can
break RSA and ECC. Anything that must stay secret longer than that is already
exposed.

This system does the four things the use case asks for:

1. **Inventory** — scans live servers for their real certificates and ciphers,
   records everything else in a register, and exports it as a CycloneDX 1.6 CBOM
2. **Risk scoring** — Mosca's inequality plus quantum weakness, exposure and impact
3. **Roadmap** — three phases taken from Mosca, with post-quantum targets
   (ML-KEM, ML-DSA, SLH-DSA, hybrid first) and effort estimates
4. **Crypto-agility** — every algorithm in this application is chosen by a policy
   file, and the Agility page measures that it really is

It is ordinary classical software. No quantum computer is needed to run it, and
the post-quantum algorithms it recommends run on ordinary computers too.

---

## Run it

**In VS Code:** open this folder, run `pip install flask cryptography` in the
terminal once, then press **F5**. Full notes in **VSCODE.md**.

**On Windows without VS Code:** double click **setup.bat** once, then
**run.bat**.

From a command prompt:

```
cd crypto_audit_system
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

On Mac or Linux the activate line is `source venv/bin/activate`.

Then open http://127.0.0.1:5000 and sign in with `admin` / `ChangeMe2026!`

For a server, see **DEPLOY.md** (Waitress, HTTPS, backups, hardening).

Other ways to start it:

```
python app.py --network   other machines on the network can reach it
python app.py --https     over https, run python make_cert.py first
```

The startup message prints the exact address to open. Full instructions for
another machine are in **SETUP.md**.

Press Ctrl+C to stop. The database fills itself with 88 sample systems on the
first run.

## Test the engines on their own

Each of these prints to the terminal. No web server involved.

```
python crypto_rules.py          the knowledge base
python risk_engine.py           the scoring formula
python recommendation_engine.py the full ranking and plan
python database.py              creates the database
```

---

## The pages

| Page | What it is for |
|---|---|
| Dashboard `/` | How bad is it. Counters, two charts, top five systems. |
| Add a system `/add` | Where data gets in. Seven fields, validated. |
| Systems `/inventory` | The working list, sorted worst first. |
| Score working `/results` | The formula worked out per system. The "prove it" page. |
| Analysis `/analysis` | Three charts. The picture version. |
| Roadmap `/plan` | Six steps, three phases, what to replace with. |
| Departments `/departments` | Which parts of the organisation carry the exposure. |
| Protect `/protect` | Upload a file and it is encrypted, plus a six layer plan. |
| Scan `/scan` | Read what a live server actually runs. Measured, not typed. |
| Code `/code` | Upload a program or a .zip; finds old algorithms inside it. |
| Agility `/agility` | Crypto-agility, measured on this application. Change the policy here. |
| Certificate expiry `/expiry` | Certificates running out, soonest first. |
| Email alerts `/alerts` | Email people before a certificate expires. |
| Audit log `/log` | Who changed what, and when. Append only. |
| Password `/password` | Change your own password. |
| Accounts `/users` | Create auditors and viewers. |
| Printable report `/report` | Six sections, print to PDF. What you hand someone. |
| Import a spreadsheet `/import` | Upload a CSV instead of typing systems in one at a time. |

---

## The Python modules

**crypto_rules.py** — the knowledge base, and the only file that knows about
algorithms. It answers the harvest-now-decrypt-later question: will a quantum
computer read what this protects? RSA, ECC and Diffie-Hellman are broken by
Shor's algorithm at any key size, so RSA-4096 is no safer than RSA-2048. AES-128
and SHA-256 are weakened by Grover; AES-256 and SHA-384 are safe. ML-KEM, ML-DSA,
SLH-DSA and the X25519 + ML-KEM hybrid are post-quantum. 3DES, SHA-1, MD5, RC4
and undersized keys are broken today.

**risk_engine.py** — Mosca's inequality and the score. See "The scoring" below.
The quantum horizon, the weights and the exposure scale are all set here.

**recommendation_engine.py** — sorts worst first, assigns priority numbers,
picks the recommendation, maps each weak algorithm to its replacement, and
builds the three funding phases.

**database.py** — SQLite. Uses `?` placeholders rather than string
concatenation, which is what prevents SQL injection.

**scanner.py** — connects to a live server and reads its real certificate.
Uses only `ssl` and `socket`, both built into Python. Reports the TLS version,
the cipher suite, the certificate's issuer and expiry, and the public key size
read out of the certificate bytes. A failed scan is reported, never fatal, so a
run across 200 hosts does not stop at the first one that is down.

Every scan is stored, including the failures, so each host builds a history.
The Expiry page lists them soonest first and bands them: expired, under 14 days,
under 30, under 90, and fine. **Re-scan everything** repeats the whole set, and
**History** shows one host over time — if the certificate line changes between
two rows, that is a migration measured rather than reported.

That page exists because an expired certificate takes a service offline the
same morning, while a weak algorithm is a problem for 2036. It is the one part
of this tool that prevents a problem next month.

**notifier.py** — emails people before a certificate expires. Anyone who
scans a host can ask to be reminded 7, 14, 30, 60 or 90 days before. It emails
once when the line is crossed and again only if it gets a week closer, so a 30
day warning is not thirty emails. With no mail account configured it saves the
emails to an `outbox` folder instead, so the feature works with no setup. Real
sending and daily scheduling are in **ALERTS.md**. The mail password is read
from the environment and never stored in the code or the database.

**Security.** Every form carries a one-time token, so another website cannot
make your browser change anything here (CSRF). Deleting a system and re-scanning
are POST-only, never a link. Five failed sign-ins from one account or address
lock it for 15 minutes, and every attempt is logged. Anyone can change their own
password from the header. Blocked forged requests and lockouts appear in the
audit log.

**auth.py** — accounts, passwords and two roles. An auditor can add, import,
scan and delete; a viewer can only look. Passwords are stored as a PBKDF2-SHA256
hash over 250,000 rounds with a random salt, which is the same approach this
tool recommends on its own advisory page.

**audit_log.py** — every change recorded with who, what, when and from where.
Append only: there is no function in the file that deletes a row.

**static/js/protect.js** — encrypts uploaded files with AES-256-GCM, in the
browser, using the Web Crypto API. The file is deliberately never sent to the
server: a register of weak systems is one thing to hold, the actual patient
records are another, and they have no business leaving the machine they are on.

Key derivation is PBKDF2-SHA256 over 250,000 rounds. Protected files carry a
`CAS1` header so the site can tell whether it produced them, rather than
trusting the file name. AES-GCM also authenticates, so a file altered after it
was protected will not open even with the correct passphrase.

There is no passphrase recovery, by design. A recovery route is a second way in.

**advisory.py** — turns a risk score into a protection plan. The audit says
what is wrong; this says what to do about it. Advice is built in six layers:
immediate containment, the algorithm replacement, re-encrypting stored data,
key management, verification, and stopping it recurring. The advice adapts to
the algorithm family and the data lifetime, so a hash gets different guidance
from a block cipher, and short lived data is not told to re-encrypt its history.

**csv_import.py** — reads a spreadsheet and validates every row. A bad row is
reported by line number and skipped; the rest still load, because a real
inventory of two hundred systems will have a few typos and dying on row forty
is useless.

**crypto_service.py** — the crypto-agility layer. Every part of the application
that needs cryptography asks this file, and this file reads its algorithms from
`crypto_policy.json`. Stored passwords and signatures carry the name of the
algorithm that made them, so a policy change never breaks old data: passwords
are quietly re-hashed at the next sign in. It also counts any cryptography used
directly elsewhere in the code, which is the Agility page's first measure.

**code_scan.py** — finds old cryptography written inside source code. Upload a
file or a .zip and it lists every line using MD5, SHA-1, DES, 3DES, RC4, old TLS,
RSA, elliptic curve or AES-128, with what to use instead. Skips `node_modules`,
`venv` and build folders. Nothing is stored: the code is read in memory and
thrown away.

**cbom.py** — writes the inventory as a Cryptographic Bill of Materials in
CycloneDX 1.6, one component per system and per scanned certificate, with NIST
quantum security levels. Checked against the official CycloneDX 1.6 schema.

**app.py** — routes and form validation. Contains no maths. Every number on
every page comes from the engines above.

---

## The scoring

**Mosca's inequality** decides whether a system is already too late:

```
X  +  Y  >  Z

X  years the data must stay secret
Y  years it will take to migrate the system
Z  years until a quantum computer can break its algorithm
```

Z is 10 years for RSA, ECC and Diffie-Hellman (change `QUANTUM_HORIZON` in
`risk_engine.py`), zero for algorithms already broken today, and does not apply
to quantum-safe algorithms. If X + Y is bigger than Z, data copied today will be
readable while it still matters.

Each system is then scored out of 100:

```
risk = 40 x gap  +  25 x weakness  +  20 x exposure  +  15 x impact
```

| Factor | What it measures |
|---|---|
| gap | Years past Mosca's deadline, scaled against 40 years |
| weakness | 1 if a quantum computer breaks it, 0.4 for AES-128, 0 for post-quantum |
| exposure | Public internet 1.0, partner network 0.7, internal LAN 0.4, air-gapped 0.1 |
| impact | Data sensitivity and system criticality together |

75 and above is Critical, 55 High, 35 Medium, below that Low.

Because nobody knows when a quantum computer will arrive, Risk Analysis also runs
the whole audit at 7 and 15 years. A system that fails under all three guesses is
urgent whatever happens.

---

## Questions worth having an answer to

**Why does RSA-4096 score the same as RSA-2048?**

Because Shor's algorithm breaks RSA at any key size. A bigger key helps against
today's computers and does nothing against a quantum one. Recommending a bigger
RSA key would be the wrong answer to this use case.

**Where is the quantum computing?**

There is none, deliberately. The threat is quantum; the defence is classical
software. ML-KEM and ML-DSA are ordinary algorithms that run on ordinary
computers but are designed so that quantum computers cannot break them either.

**Why is migration time part of the score?**

That is Mosca's point. A system whose data only needs to stay secret for five
years looks safe against a ten-year quantum horizon, but if migrating it takes
six years, it is already too late to start.

**What happens with an algorithm the tool does not know?**

It is assumed weak and flagged for manual review. Unknown is treated as unsafe
until a person confirms otherwise.

**How do you know the application itself is crypto-agile?**

The Agility page searches every Python file in it for cryptography used
directly instead of through the crypto service. The answer is zero. Changing
the policy switches password hashing, signatures and certificate keys without
editing any code, and old passwords and signatures keep working.

---

## Changing the rules

Everything tunable lives in two places.

Algorithm risk and key size thresholds: `CRYPTO_RULES` in `crypto_rules.py`.
The four weights, the quantum horizon and the exposure scale: `risk_engine.py`.
Which algorithms this application itself uses: `crypto_policy.json`, or the
Agility page.
Department list: `DEPARTMENTS` in `app.py`.
Colour scheme: the `:root` block at the top of `static/css/style.css`.

Edit those and every page updates. Nothing else needs touching.

---

## Working with data

**Sample data.** Eighty-eight systems across twenty-six departments load on
first run: Agriculture, Civil Supplies, Disaster Management, Education,
Endowments, Energy, Excise, Finance, Fisheries, Forest, General Admin,
Handlooms, Health, Home, IT & E-Gov, Judiciary, Labour, Mines & Geology,
Municipal Admin, Public Libraries, Revenue, Rural Development, Sports & Youth,
Tourism, Transport and Women & Child.

They cover most algorithms in the knowledge base, including deprecated ones
(3DES, MD5, SHA-1) and undersized keys (DH-1024, ECC-192), so the demo shows
the full range.

Three of them have already been migrated — the tourism website and cyclone
warning portal use the X25519 + ML-KEM-768 hybrid, and the document signing
service uses ML-DSA-65 — so the demo shows what finished looks like as well as
what is wrong. Secrecy years, migration years and exposure for the samples are
estimated from each system's name and type; they are illustrative, not real
figures from any department.

**Search and filter.** The Inventory page filters by free text, department and
risk level, and the three combine.

**Import.** Upload a CSV on the Import page. Download the template first to see
the expected columns. Rows that fail validation are listed with their line
numbers rather than silently dropped.

**Export.** The Inventory page links to a CSV of the full scored audit,
including priority, percentage, level and recommendation.

---

## Signing in

On first run an account is created and the password is shown once on the login
page:

```
username: admin
password: ChangeMe2026!
```

Create your own account under Accounts, then delete that one.

---

## Measured versus typed

Everything entered through the Add System form is **self-reported**. Somebody
says a system runs RSA-2048 and the tool believes them.

The Scan page is different. It connects to the host, reads the certificate and
reports what is actually there. The key size is read out of the certificate
bytes, and the page says which numbers were measured and which were inferred.

That distinction is the point. A tool that quietly guesses is worse than one
that says it guessed.

What it can see: anything reachable over the network.
What it cannot: encryption at rest in a database, or algorithms inside
application code. Those still need a person.

---

## What is not built yet

**A CERT-In audit.** Government web applications in India are normally audited
by a CERT-In empanelled auditor before going live.

**HTTPS.** Right now the tool trusts what someone typed. Python's
`ssl` module can connect to a hostname and read its actual certificate, which
turns estimated input into measured input. This is the biggest single upgrade
available and needs no extra install.

Sending a register of weak cryptography over plain HTTP is the project
contradicting itself. A self-signed certificate is enough to demonstrate it.

**A production server.** Flask's built-in one prints a warning for good reason:
it handles one request at a time. Swap to Waitress on Windows.

**The quantum component.** Add it after everything above works. The natural
shape is a second gap calculation using Mosca's inequality: if data lifetime
plus migration time exceeds the years remaining before quantum computers break
RSA, the system is already past its deadline. That slots in as a fifth factor
without disturbing the existing four.
