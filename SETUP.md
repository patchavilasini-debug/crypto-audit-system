# Running this on another PC

## The short version

1. Copy the whole folder onto the other machine
2. Double click **setup.bat** and wait
3. Double click **run.bat**
4. Open `http://127.0.0.1:5000`
5. Sign in with `admin` / `ChangeMe2026!`

That is it. Setup only needs doing once.

---

## If Python is not installed

`setup.bat` will tell you. Get it from <https://python.org/downloads>.

On the **first screen** of the installer, tick **Add python.exe to PATH**.
People miss that box and then nothing works.

---

## The four ways to start it

| Double click | What it does |
|---|---|
| `run.bat` | This machine only. `http://127.0.0.1:5000` |
| `run-network.bat` | Other machines on the same network can reach it |
| `run-https.bat` | Over HTTPS, makes a certificate first if needed |
| `check.bat` | Runs each engine on its own, to prove the backend works |

Or from a command prompt:

```
python app.py                 this machine only
python app.py --network       reachable on the network
python app.py --https         over https
python app.py --network --https --port 8443
```

The window prints the exact address to open.

---

## Letting other machines reach it

Run `run-network.bat`. The window prints two addresses, something like:

```
http://127.0.0.1:5000
http://192.168.1.45:5000
```

The second one is what other machines type into their browser.

**If they cannot reach it,** Windows Firewall is blocking the port. Open an
Administrator command prompt (right click the Start button, choose
**Terminal (Admin)**) and run:

```
netsh advfirewall firewall add rule name="Crypto Audit" dir=in action=allow protocol=TCP localport=5000
```

**If it still fails,** the network itself may be isolating devices from each
other. College and office wifi often does this on purpose. Test it by putting
both machines on a phone hotspot instead. If it works there, the app is fine
and the network was the obstacle.

---

## Starting over

The whole state lives in one file: `data\crypto_audit.db`.

Delete it and the site rebuilds itself on the next start, with the 88 sample
systems and a fresh admin account. Nothing else needs touching.

---

## Moving it to a real server

`run.bat` uses Flask's built in server, which prints a warning because it
handles one request at a time. For more than a handful of people:

```
venv\Scripts\python.exe -m waitress --host=0.0.0.0 --port=5000 app:app
```

Waitress is already installed by `setup.bat`.

Also:

- Set a real secret key so sessions survive a restart properly:
  `set CRYPTO_AUDIT_SECRET=something-long-and-random`
- Use a certificate from the organisation's own authority, not the self signed
  one `make_cert.py` produces
- Put it behind the firewall. A register of which systems are weak is useful to
  an attacker

---

## Checking the backend without the web pages

Double click `check.bat`, or run each file on its own:

```
python crypto_rules.py           the algorithm knowledge base
python risk_engine.py            the scoring formula
python recommendation_engine.py  ranking and recommendations
python advisory.py               a protection plan
python database.py               the database
python scanner.py github.com     a real scan
python auth.py                   accounts
python audit_log.py              the change log
python csv_import.py             the importer
```

Each prints its results to the screen. None of them needs Flask, a browser, or
the internet apart from the scanner.

That separation is deliberate: the algorithms were written first and the web
pages built around them, so the thinking can be checked without the interface
in the way.
