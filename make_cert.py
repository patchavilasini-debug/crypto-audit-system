# make_cert.py
# Creates a self signed certificate so the site can run over HTTPS.
#
# Run once:  python make_cert.py
#
# Browsers will warn that the certificate is not from a known authority.
# That is expected for an internal tool. A real deployment would use a
# certificate from the organisation's own authority.

import datetime
import ipaddress
import os
import socket

try:
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("This needs the cryptography library:")
    print("   pip install cryptography")
    raise SystemExit(1)

CERT_DIR = "certs"
CERT_FILE = os.path.join(CERT_DIR, "site.crt")
KEY_FILE = os.path.join(CERT_DIR, "site.key")
DAYS = 90          # short on purpose. The tool recommends 90 day certificates,
                   # so its own should not last three years.


def local_addresses():
    names = ["localhost"]
    ips = [ipaddress.ip_address("127.0.0.1")]
    try:
        host = socket.gethostname()
        names.append(host)
        for info in socket.getaddrinfo(host, None):
            addr = info[4][0]
            try:
                ip = ipaddress.ip_address(addr)
                if ip not in ips:
                    ips.append(ip)
            except ValueError:
                pass
    except Exception:
        pass
    return names, ips


def build():
    if not os.path.exists(CERT_DIR):
        os.makedirs(CERT_DIR)

    # The key type comes from the crypto policy, not from this file.
    import crypto_service
    key, key_label = crypto_service.new_certificate_key()

    names, ips = local_addresses()
    alt = [x509.DNSName(n) for n in names] + [x509.IPAddress(i) for i in ips]

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Crypto Audit System"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Internal tool"),
    ])

    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=DAYS))
            .add_extension(x509.SubjectAlternativeName(alt), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None),
                           critical=True)
            .sign(key, crypto_service.certificate_hash()))

    with open(KEY_FILE, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))

    with open(CERT_FILE, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    return names, ips, key_label


if __name__ == "__main__":
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("Certificate already exists in the certs folder.")
        print("Delete certs/site.crt and certs/site.key to make a new one.")
    else:
        names, ips, key_label = build()
        print("Created a self signed %s certificate, good for %d days."
              % (key_label, DAYS))
        print("   " + CERT_FILE)
        print("   " + KEY_FILE)
        print("")
        print("Valid for: " + ", ".join(names + [str(i) for i in ips]))
        print("")
        print("Now start the site with:")
        print("   python app.py --https")
        print("")
        print("Your browser will warn that the certificate is not from a known")
        print("authority. That is expected for an internal tool. Click through")
        print("the warning, or import the certificate on each machine.")
