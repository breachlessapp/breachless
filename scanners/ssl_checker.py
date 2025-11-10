import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse


def check_ssl_certificate(domain: str):
    """
    Checks SSL/TLS certificate validity, expiry date, and issuer for a given domain.
    Returns a dictionary with certificate details.
    """
    if not domain.startswith("https://"):
        domain = "https://" + domain

    parsed = urlparse(domain)
    hostname = parsed.hostname
    port = 443

    ctx = ssl.create_default_context()
    result = {}

    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract dates
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")

        days_remaining = (not_after - datetime.utcnow()).days

        result = {
            "valid": True,
            "issuer": dict(x[0] for x in cert["issuer"]).get("organizationName", "Unknown"),
            "subject": dict(x[0] for x in cert["subject"]).get("commonName", "Unknown"),
            "not_before": not_before.strftime("%Y-%m-%d"),
            "not_after": not_after.strftime("%Y-%m-%d"),
            "days_remaining": days_remaining
        }

    except ssl.SSLError as e:
        result = {"valid": False, "error": f"SSL error: {str(e)}"}
    except socket.timeout:
        result = {"valid": False, "error": "Connection timed out"}
    except Exception as e:
        result = {"valid": False, "error": str(e)}

    return result
