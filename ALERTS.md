# Certificate expiry emails

## How to use it

1. Go to **Scan** and scan a host
2. Under the result, type your email and pick how early you want warning
3. Press **Remind me**

Then go to **Alerts** and press **Check now and send**.

## Outbox mode (the default)

With no mail account set up, emails are not sent. They are saved as files in
the `outbox` folder, and listed at the bottom of the Alerts page. Click one to
read it exactly as it would arrive.

This means the whole feature works and can be shown without any setup.

## Sending real email with Gmail

**1. Make an app password.** Gmail will not accept your normal password from a
program.

- Go to <https://myaccount.google.com/security>
- Turn on **2-Step Verification** if it is not on already
- Search the page for **App passwords**
- Create one, name it "Crypto Audit"
- Copy the 16 letter code it shows

**2. Tell the site about it.** In Command Prompt, before starting the site:

```
set CRYPTO_AUDIT_SMTP_HOST=smtp.gmail.com
set CRYPTO_AUDIT_SMTP_PORT=587
set CRYPTO_AUDIT_SMTP_USER=youraddress@gmail.com
set CRYPTO_AUDIT_SMTP_PASS=abcdabcdabcdabcd
python app.py
```

In VS Code's terminal, which is usually PowerShell, the lines are:

```
$env:CRYPTO_AUDIT_SMTP_HOST="smtp.gmail.com"
$env:CRYPTO_AUDIT_SMTP_PORT="587"
$env:CRYPTO_AUDIT_SMTP_USER="youraddress@gmail.com"
$env:CRYPTO_AUDIT_SMTP_PASS="abcdabcdabcdabcd"
python app.py
```

The Alerts page will change from **Outbox mode** to **Sending real email**.

**3. Test it.** Use **Send a test email** on the Alerts page. If it arrives,
alerts will too.

These settings last until you close the window. The password is never written
into the code or the database, which is deliberate.

## Checking every day automatically

The **Check now and send** button needs somebody to press it. To have it run on
its own each morning, use Windows Task Scheduler:

1. Search the Start menu for **Task Scheduler** and open it
2. Click **Create Basic Task**
3. Name it "Certificate expiry check", press Next
4. Choose **Daily**, pick a time such as 9:00, press Next
5. Choose **Start a program**, press Next
6. **Program:** browse to `run-alerts.bat` in this folder
7. **Start in:** the folder path itself, for example
   `C:\Users\you\Downloads\crypto_audit_system`
8. Finish

`run-alerts.bat` checks every subscription once and exits. It does not need
the website to be running.

For real email from the scheduled task, put the four `set` lines at the top of
`run-alerts.bat` itself.

## How often it emails

- Once when a certificate crosses the warning line you chose
- Again only if it gets at least a week closer
- Straight away if the server stops answering

So a 30 day warning sends a handful of emails, not thirty.

## Run the check from the command line

```
python notifier.py
```

Prints what it checked, what it sent, and why it skipped the rest.
