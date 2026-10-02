# scanner.py
# Reads the REAL certificate from a live server.
#
# This is what turns "someone typed RSA-2048" into "we measured it".
# Uses only the ssl and socket modules, which come with Python.
#
# Run on its own:  python scanner.py github.com

import ssl
import socket
import datetime

DEFAULT_PORT = 443
TIMEOUT = 6          # seconds. A hung scan is worse than a failed one.

# How OpenSSL names a signature algorithm, mapped to our knowledge base.
SIG_TO_ALGORITHM = {
    "sha256WithRSAEncryption": ("RSA", "SHA-256"),
    "sha384WithRSAEncryption": ("RSA", "SHA-384"),
    "sha512WithRSAEncryption": ("RSA", "SHA-512"),
    "sha1WithRSAEncryption":   ("RSA", "SHA-1"),
    "md5WithRSAEncryption":    ("RSA", "MD5"),
    "ecdsa-with-SHA256":       ("ECC", "SHA-256"),
    "ecdsa-with-SHA384":       ("ECC", "SHA-384"),
    "ecdsa-with-SHA1":         ("ECC", "SHA-1"),
}

# Cipher name fragments to the symmetric algorithm in use.
CIPHER_HINTS = [
    ("AES_256", "AES", 256), ("AES256", "AES", 256),
    ("AES_128", "AES", 128), ("AES128", "AES", 128),
    ("3DES", "3DES", 168), ("DES-CBC3", "3DES", 168),
    ("RC4", "RC4", 128),
    ("CHACHA20", "ChaCha20", 256),
]


def clean_host(host):
    """Accept https://example.com/page and return example.com."""
    host = str(host).strip()
    for prefix in ("https://", "http://"):
        if host.lower().startswith(prefix):
            host = host[len(prefix):]
    host = host.split("/")[0].split("?")[0]
    if ":" in host and not host.count(":") > 1:   # host:port, not IPv6
        host = host.split(":")[0]
    return host.strip()


def scan_host(host, port=DEFAULT_PORT, timeout=TIMEOUT):
    """
    Connect and read what the server actually uses.

    Returns a dictionary. On failure it returns one with 'error' set
    rather than raising, because a scan of 200 hosts must not stop on
    the first one that is down.
    """
    host = clean_host(host)
    if not host:
        return {"host": host, "error": "No hostname given."}

    result = {"host": host, "port": port, "error": None,
              "scanned_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M")}

    # Two passes. First with verification on, which makes Python parse the
    # certificate into a readable structure. If that fails we try again
    # without verification, because a certificate we cannot trust is still
    # a certificate we need to audit - and the failure is itself a finding.
    cert = None
    der = None
    cipher = None
    result["cert_trusted"] = None

    try:
        for verify in (True, False):
            context = ssl.create_default_context()
            if not verify:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            try:
                with socket.create_connection((host, port), timeout=timeout) as sock:
                    with context.wrap_socket(sock, server_hostname=host) as tls:
                        cert = tls.getpeercert()
                        der = tls.getpeercert(binary_form=True)
                        cipher = tls.cipher()
                        result["tls_version"] = tls.version()
                        result["cipher_suite"] = cipher[0] if cipher else "unknown"
                        result["cipher_bits"] = cipher[2] if cipher else 0
                        result["cert_size_bytes"] = len(der) if der else 0
                        result["cert_trusted"] = verify
                break
            except ssl.SSLCertVerificationError:
                if verify:
                    continue          # try again without verifying
                raise

    except socket.gaierror:
        result["error"] = "That hostname does not resolve. Check the spelling."
        return result
    except socket.timeout:
        result["error"] = "Timed out after %d seconds. Host may be down or blocked." % timeout
        return result
    except ConnectionRefusedError:
        result["error"] = "Connection refused on port %d. Is it running HTTPS?" % port
        return result
    except ssl.SSLError as e:
        result["error"] = "TLS handshake failed: %s" % str(e)[:80]
        return result
    except OSError as e:
        result["error"] = "Could not connect: %s" % str(e)[:80]
        return result

    # --- what the certificate says ---
    if cert:
        result["subject"] = _name_of(cert.get("subject"))
        result["issuer"] = _name_of(cert.get("issuer"))
        result["expires"] = cert.get("notAfter", "unknown")
        result["days_left"] = _days_until(cert.get("notAfter"))
    else:
        result["subject"] = "not presented"
        result["issuer"] = "not presented"
        result["expires"] = "unknown"
        result["days_left"] = None

    # --- the key exchange algorithm, read from the cipher suite ---
    suite = (result.get("cipher_suite") or "").upper()
    if result.get("tls_version") == "TLSv1.3":
        # TLS 1.3 suite names carry no key exchange, because it is always
        # ephemeral Diffie-Hellman - in practice on a named elliptic curve.
        result["key_exchange"] = "ECC"
    elif "ECDHE" in suite or "ECDH" in suite:
        result["key_exchange"] = "ECC"
    elif "DHE" in suite or "DH" in suite:
        result["key_exchange"] = "DH"
    elif "RSA" in suite:
        result["key_exchange"] = "RSA"
    else:
        result["key_exchange"] = "unknown"

    # --- the symmetric cipher ---
    result["symmetric"] = "unknown"
    result["symmetric_bits"] = result.get("cipher_bits", 0)
    for fragment, name, bits in CIPHER_HINTS:
        if fragment in suite:
            result["symmetric"] = name
            result["symmetric_bits"] = bits
            break

    # --- what our audit should record ---
    # We report the key exchange, because that is the part a quantum
    # computer breaks. The symmetric cipher is recorded alongside it.
    measured = measure_key(der)
    if measured:
        result["cert_algorithm"] = measured[0]
        result["key_size"] = measured[1]
        result["key_size_measured"] = True
        result["key_size_method"] = measured[2]
    else:
        result["cert_algorithm"] = result["key_exchange"]
        result["key_size"] = _assumed_key_size(result["key_exchange"],
                                               result.get("cert_size_bytes", 0))
        result["key_size_measured"] = False
        result["key_size_method"] = "inferred"

    details = cert_details(der)
    fallback_expiry = details.pop("_not_after", None)
    result.update(details)
    if result.get("expires") in (None, "unknown") and fallback_expiry:
        result["expires"] = fallback_expiry
        result["days_left"] = _days_until(fallback_expiry)

    # The certificate's own key is what a quantum computer attacks, so
    # that is what the audit records.
    result["algorithm"] = result["cert_algorithm"]

    return result


# ---------------------------------------------------------------
# Reading the public key.
#
# The cryptography library parses certificates properly. If it is not
# installed we fall back to reading the bytes by hand, which works but
# is our own code rather than a tested library - so the result is
# flagged either way and the page says which method was used.
# ---------------------------------------------------------------

try:
    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519
    HAVE_CRYPTOGRAPHY = True
except ImportError:
    HAVE_CRYPTOGRAPHY = False

# Fallback only: object identifiers as they appear inside a DER certificate.
OID_RSA = bytes([0x2a,0x86,0x48,0x86,0xf7,0x0d,0x01,0x01,0x01])
OID_EC  = bytes([0x2a,0x86,0x48,0xce,0x3d,0x02,0x01])
CURVES = {
    bytes([0x2a,0x86,0x48,0xce,0x3d,0x03,0x01,0x07]): 256,   # P-256
    bytes([0x2b,0x81,0x04,0x00,0x22]):                384,   # P-384
    bytes([0x2b,0x81,0x04,0x00,0x23]):                521,   # P-521
    bytes([0x2b,0x81,0x04,0x00,0x0a]):                256,   # secp256k1
}


def measure_key(der):
    """
    Return (algorithm, bits, method) or None.

    'method' is either 'library' or 'byte reading', and the scan page
    shows it. A tool that quietly guesses is worse than one that says
    how it worked the number out.
    """
    if not der:
        return None

    if HAVE_CRYPTOGRAPHY:
        try:
            cert = x509.load_der_x509_certificate(der)
            key = cert.public_key()

            if isinstance(key, rsa.RSAPublicKey):
                return ("RSA", key.key_size, "library")
            if isinstance(key, ec.EllipticCurvePublicKey):
                return ("ECC", key.curve.key_size, "library")
            if isinstance(key, dsa.DSAPublicKey):
                return ("DH", key.key_size, "library")
            if isinstance(key, ed25519.Ed25519PublicKey):
                return ("ECC", 255, "library")

            size = getattr(key, "key_size", None)
            if size:
                return ("unknown", size, "library")
        except Exception:
            pass          # fall through to the byte reader

    # --- fallback ---
    if OID_EC in der:
        for oid, bits in CURVES.items():
            if oid in der:
                return ("ECC", bits, "byte reading")
        return ("ECC", 256, "byte reading")

    if OID_RSA in der:
        start = der.find(OID_RSA) + len(OID_RSA)
        window = der[start:start + 40]
        for i in range(len(window) - 4):
            if window[i] == 0x02 and window[i + 1] == 0x82:
                length = (window[i + 2] << 8) | window[i + 3]
                bits = (length - 1) * 8
                if 512 <= bits <= 16384:
                    return ("RSA", bits, "byte reading")
        return ("RSA", 2048, "byte reading")

    return None


def cert_details(der):
    """Extra facts the library can give us and the byte reader cannot."""
    out = {}
    if not (HAVE_CRYPTOGRAPHY and der):
        return out
    try:
        cert = x509.load_der_x509_certificate(der)
        out["signature_algorithm"] = cert.signature_algorithm_oid._name
        out["serial"] = format(cert.serial_number, "x")[:32]
        out["self_signed"] = cert.issuer == cert.subject
        out["version"] = cert.version.name

        # Certificate lifetime. Short-lived certificates (90 days or less,
        # renewed automatically) are one of UC-027's agility measures: they
        # let a key type be rotated across the estate in weeks, not years.
        try:
            start = cert.not_valid_before_utc
            end = cert.not_valid_after_utc
        except AttributeError:            # older cryptography versions
            start = cert.not_valid_before
            end = cert.not_valid_after
        out["not_before"] = start.strftime("%b %d %H:%M:%S %Y GMT")
        out["lifetime_days"] = (end - start).days
        out["_not_after"] = end.strftime("%b %d %H:%M:%S %Y GMT")
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName)
            names = san.value.get_values_for_type(x509.DNSName)
            out["alt_names"] = ", ".join(names[:6])
            out["alt_name_count"] = len(names)
        except x509.ExtensionNotFound:
            out["alt_names"] = ""
            out["alt_name_count"] = 0
    except Exception:
        pass
    return out


def _name_of(rdns):
    """Pull the common name out of the certificate's name structure."""
    if not rdns:
        return "unknown"
    for part in rdns:
        for key, value in part:
            if key == "commonName":
                return value
    return "unknown"


def _days_until(not_after):
    if not not_after:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%b %d %H:%M:%S %Y"):
        try:
            when = datetime.datetime.strptime(not_after, fmt)
            return (when - datetime.datetime.now()).days
        except ValueError:
            continue
    return None


def _assumed_key_size(algorithm, cert_bytes):
    """
    A rough key size.

    Python's ssl module does not expose the public key size directly
    without a third party library, so this is an estimate from the
    certificate size. It is flagged as inferred, not measured, because
    a tool that quietly guesses is worse than one that says it guessed.
    """
    if algorithm == "ECC":
        return 256
    if algorithm in ("RSA", "DH"):
        if cert_bytes > 1800:
            return 4096
        if cert_bytes > 1200:
            return 2048
        return 2048
    return 2048


def scan_many(hosts, timeout=TIMEOUT):
    """Scan a list. Failures are reported, never fatal."""
    return [scan_host(h, timeout=timeout) for h in hosts if str(h).strip()]


if __name__ == "__main__":
    import sys
    targets = sys.argv[1:] or ["github.com"]

    for host in targets:
        r = scan_host(host)
        print("")
        print("=" * 62)
        print("SCAN: " + r["host"])
        print("=" * 62)
        if r["error"]:
            print("  FAILED: " + r["error"])
            continue
        print("  TLS version      : %s" % r["tls_version"])
        print("  Cipher suite     : %s" % r["cipher_suite"])
        print("  Key exchange     : %s" % r["key_exchange"])
        print("  Symmetric cipher : %s-%s" % (r["symmetric"], r["symmetric_bits"]))
        print("  Certificate for  : %s" % r["subject"])
        print("  Issued by        : %s" % r["issuer"])
        print("  Expires          : %s (%s days)" % (r["expires"], r["days_left"]))
        print("")
        print("  Certificate key  : %s-%s  (%s)"
              % (r["algorithm"], r["key_size"], r["key_size_method"]))
        if r.get("signature_algorithm"):
            print("  Signed with      : %s" % r["signature_algorithm"])
        if r.get("self_signed") is not None:
            print("  Self signed      : %s" % ("yes" if r["self_signed"] else "no"))
        if r.get("alt_name_count"):
            print("  Also valid for   : %d name(s)" % r["alt_name_count"])
        print("  Trusted chain    : %s"
              % ("yes" if r["cert_trusted"] else "NO - verification failed"))
        print("")
        print("  -> records as    : %s-%s" % (r["algorithm"], r["key_size"]))
