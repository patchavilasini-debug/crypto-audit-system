# Running this in VS Code

## First time

**1.** Open VS Code, then **File → Open Folder**.
Select the `crypto_audit_system` folder. Not the one above it — the one that
has `app.py` directly inside.

**2.** Open a terminal: **Terminal → New Terminal**, or press ``Ctrl + ` ``

**3.** Install what it needs:

```
pip install flask cryptography
```

If `pip` is not recognised, use:

```
python -m pip install flask cryptography
```

## Every time after that

Press **F5**.

The site starts, and the terminal prints the address. Ctrl+click the link to
open it.

If F5 asks which configuration to use, choose **Run the site**.

Or type it yourself in the terminal:

```
python app.py
```

## Sign in

```
username: admin
password: ChangeMe2026!
```

Make your own account under **Accounts**, then delete that one.

## The other run options

Press **Ctrl+Shift+D** to open the Run panel, then pick from the dropdown:

| Configuration | What it does |
|---|---|
| Run the site | This machine only |
| Run on the network | Other machines can reach it |
| Run over HTTPS | Needs `python make_cert.py` first |
| Test: knowledge base | Runs `crypto_rules.py` on its own |
| Test: scoring formula | Runs `risk_engine.py` on its own |
| Test: ranking and advice | Runs `recommendation_engine.py` |
| Test: scan a real host | Scans github.com from the terminal |

The four test configurations run one engine with no web server involved. That
is how to show the backend works without the interface in the way.

## Stopping it

Click in the terminal and press **Ctrl+C**, or press the red stop square in
the debug toolbar.

## If the terminal says python is not recognised

Python is not on the PATH. Reinstall it from <https://python.org/downloads>
and tick **Add python.exe to PATH** on the first screen.

## If the port is already in use

An older copy is still running. Close every terminal, or start on a different
port:

```
python app.py --port 5001
```
