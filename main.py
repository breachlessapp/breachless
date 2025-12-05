from fastapi import FastAPI
from scanners.headers import check_security_headers
from scanners.ssl_checker import check_ssl_certificate
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI(
    title="Breachless API",
    description="Automated Website Security Audit API",
    version="0.1.0"
)

# ✅ CORS must be OUTSIDE the FastAPI() constructor
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "https://breachless.app",
        "https://www.breachless.app",
    ],
    allow_origin_regex=r"https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.get("/")
def home():
    return {"message": "Welcome to Breachless API"}

@app.get("/scan/{domain}")
def scan_domain(domain: str):
    """
    Run a simple security headers scan for a given domain.
    Example: /scan/example.com
    """
    results = check_security_headers(domain)
    return {"domain": domain, "headers": results}

@app.get("/ssl/{domain}")
def ssl_scan(domain: str):
    """
    Run an SSL/TLS certificate check for a given domain.
    Example: /ssl/example.com
    """
    results = check_ssl_certificate(domain)
    return {"domain": domain, "ssl": results}


@app.get("/audit/{domain}")
def full_audit(domain: str):
    headers_result = check_security_headers(domain)
    ssl_result = check_ssl_certificate(domain)

    # Count how many headers are missing
    missing_headers = [h for h, v in headers_result.items() if v == "❌ Missing"]
    present_headers = len(headers_result) - len(missing_headers)

    # ---- SCORING SYSTEM ----
    # 6 headers = 60 points max (10 each)
    header_score = present_headers / len(headers_result) * 60  

    # SSL score = 40 points if valid, 0 otherwise
    ssl_score = 40 if ssl_result.get("valid", False) else 0

    total_score = int(header_score + ssl_score)

    # Convert score → letter grade
    if total_score >= 90:
        letter = "A"
    elif total_score >= 80:
        letter = "B"
    elif total_score >= 70:
        letter = "C"
    elif total_score >= 60:
        letter = "D"
    else:
        letter = "F"

    summary = {
        "total_headers_checked": len(headers_result),
        "headers_missing": len(missing_headers),
        "ssl_valid": ssl_result.get("valid", False),
        "score": total_score,
        "letter_grade": letter,
    }

    report = {
        "domain": domain,
        "summary": summary,
        "headers": headers_result,
        "ssl": ssl_result,
    }

    return report

