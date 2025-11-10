import requests

def check_security_headers(domain: str):
    """
    Checks important HTTP security headers for a given domain.
    Returns a dictionary showing which headers are present or missing.
    """
    if not domain.startswith("http"):
        domain = "https://" + domain

    try:
        response = requests.get(domain, timeout=10)
        headers = response.headers
    except Exception as e:
        return {"error": f"Could not fetch {domain}: {e}"}

    required_headers = [
        "Content-Security-Policy",
        "Strict-Transport-Security",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy"
    ]

    results = {}
    for header in required_headers:
        results[header] = "✅ Present" if header in headers else "❌ Missing"

    return results