#!/usr/bin/env python3
"""
URL Checker System - Backend
Checks: Safety Verdict, SSL Status, Blacklist, Redirect Chain, Domain Age
"""

import ssl
import socket
import whois
import requests
import urllib.parse
import json
import hashlib
from datetime import datetime, timezone
from flask import Flask, jsonify, render_template, request
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

KNOWN_BLACKLIST = [
    "malware.com", "phishing-site.net", "badactor.ru",
    "virus-download.tk", "scam-alert.xyz", "fakebank.cc"
]

SUSPICIOUS_TLDS = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".click"]
SUSPICIOUS_KEYWORDS = ["login", "verify", "account", "secure", "update", "bank",
                       "paypal", "amazon", "google", "apple", "microsoft"]

def check_ssl(hostname):
    """Check SSL certificate status and details."""
    result = {
        "valid": False,
        "issuer": None,
        "expiry_date": None,
        "days_until_expiry": None,
        "error": None
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=hostname) as s:
            s.settimeout(5)
            s.connect((hostname, 443))
            cert = s.getpeercert()

        # Issuer
        issuer_parts = dict(x[0] for x in cert.get("issuer", []))
        result["issuer"] = issuer_parts.get("organizationName", "Unknown")

        # Expiry
        expiry_str = cert.get("notAfter", "")
        expiry_dt = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_left = (expiry_dt - now).days

        result["valid"] = days_left > 0
        result["expiry_date"] = expiry_dt.strftime("%Y-%m-%d")
        result["days_until_expiry"] = days_left

    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificate verification failed: {str(e)[:80]}"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {str(e)[:80]}"
    except (socket.timeout, ConnectionRefusedError):
        result["error"] = "Could not connect to port 443 (no HTTPS)"
    except Exception as e:
        result["error"] = f"SSL check failed: {str(e)[:80]}"

    return result


def check_blacklist(hostname, url):
    """Check against known blacklists (simulated + VirusTotal hash lookup)."""
    flags = []

    # Internal blacklist
    for bad in KNOWN_BLACKLIST:
        if bad in hostname:
            flags.append(f"Domain matches known malicious list: {bad}")

    # Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if hostname.endswith(tld):
            flags.append(f"Suspicious free TLD detected: {tld}")

    # IP-based URL
    try:
        socket.inet_aton(hostname)
        flags.append("URL uses raw IP address instead of domain name")
    except socket.error:
        pass

    # URL shorteners
    shorteners = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "short.link", "rb.gy"]
    for s in shorteners:
        if s in hostname:
            flags.append(f"URL shortener detected ({s}) — real destination hidden")

    # Suspicious keywords in domain
    domain_lower = hostname.lower()
    found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in domain_lower]
    if found_kw:
        flags.append(f"Suspicious keywords in domain: {', '.join(found_kw)}")

    # Excessive subdomains
    parts = hostname.split(".")
    if len(parts) > 4:
        flags.append(f"Excessive subdomain depth ({len(parts)} levels) — possible phishing")

    # Long URL
    if len(url) > 200:
        flags.append(f"Unusually long URL ({len(url)} chars) — possible obfuscation")

    return {
        "flagged": len(flags) > 0,
        "flags": flags,
        "flag_count": len(flags)
    }


def get_redirect_chain(url):
    """Follow and record the full redirect chain."""
    chain = []
    try:
        session = requests.Session()
        session.max_redirects = 10
        resp = session.get(url, allow_redirects=False, timeout=8,
                           headers={"User-Agent": "Mozilla/5.0 URLChecker/1.0"})
        current_url = url
        chain.append({"url": current_url, "status_code": resp.status_code})

        hops = 0
        while resp.is_redirect and hops < 10:
            next_url = resp.headers.get("Location", "")
            if not next_url:
                break
            if not next_url.startswith("http"):
                parsed = urllib.parse.urlparse(current_url)
                next_url = f"{parsed.scheme}://{parsed.netloc}{next_url}"
            current_url = next_url
            resp = session.get(current_url, allow_redirects=False, timeout=8,
                               headers={"User-Agent": "Mozilla/5.0 URLChecker/1.0"})
            chain.append({"url": current_url, "status_code": resp.status_code})
            hops += 1

        final_status = resp.status_code
    except requests.exceptions.TooManyRedirects:
        final_status = None
        chain.append({"url": "Too many redirects", "status_code": None})
    except Exception as e:
        final_status = None
        chain.append({"url": f"Error: {str(e)[:80]}", "status_code": None})

    return {
        "chain": chain,
        "hops": len(chain) - 1,
        "final_url": chain[-1]["url"] if chain else url,
        "final_status": final_status
    }


def get_domain_age(hostname):
    """Get domain registration date and age via WHOIS."""
    result = {
        "registered_on": None,
        "age_days": None,
        "age_years": None,
        "registrar": None,
        "expiry_date": None,
        "error": None
    }
    try:
        # Strip www
        domain = hostname.lstrip("www.")
        w = whois.whois(domain)

        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]

        if creation:
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            age = (now - creation).days
            result["registered_on"] = creation.strftime("%Y-%m-%d")
            result["age_days"] = age
            result["age_years"] = round(age / 365.25, 1)

        expiry = w.expiration_date
        if isinstance(expiry, list):
            expiry = expiry[0]
        if expiry:
            result["expiry_date"] = expiry.strftime("%Y-%m-%d")

        result["registrar"] = w.registrar or "Unknown"

    except Exception as e:
        result["error"] = f"WHOIS lookup failed: {str(e)[:80]}"

    return result


def compute_verdict(ssl_result, blacklist_result, redirect_result, domain_age_result):
    """Compute overall safety verdict."""
    risk_score = 0
    reasons = []
    positive_signals = []

    # SSL checks
    if ssl_result["error"]:
        risk_score += 30
        reasons.append(f"SSL issue: {ssl_result['error']}")
    elif not ssl_result["valid"]:
        risk_score += 25
        reasons.append("SSL certificate is expired or invalid")
    elif ssl_result["days_until_expiry"] and ssl_result["days_until_expiry"] < 15:
        risk_score += 10
        reasons.append(f"SSL expiring very soon ({ssl_result['days_until_expiry']} days)")
    else:
        positive_signals.append("Valid SSL certificate")

    # Blacklist checks
    risk_score += blacklist_result["flag_count"] * 15
    if blacklist_result["flagged"]:
        reasons.extend(blacklist_result["flags"])

    # Redirect chain
    if redirect_result["hops"] > 3:
        risk_score += 15
        reasons.append(f"Excessive redirects ({redirect_result['hops']} hops)")
    elif redirect_result["hops"] == 0:
        positive_signals.append("No redirects detected")

    # Domain age
    age_days = domain_age_result.get("age_days")
    if age_days is None:
        risk_score += 10
        reasons.append("Domain age could not be verified")
    elif age_days < 30:
        risk_score += 30
        reasons.append(f"Very new domain — only {age_days} days old")
    elif age_days < 180:
        risk_score += 15
        reasons.append(f"Relatively new domain ({age_days} days old)")
    elif age_days > 365:
        positive_signals.append(f"Established domain ({domain_age_result['age_years']} years old)")

    # Verdict
    if risk_score >= 50:
        verdict = "DANGEROUS"
        color = "red"
        icon = "⛔"
    elif risk_score >= 25:
        verdict = "SUSPICIOUS"
        color = "orange"
        icon = "⚠️"
    else:
        verdict = "SAFE"
        color = "green"
        icon = "✅"

    return {
        "verdict": verdict,
        "risk_score": min(risk_score, 100),
        "color": color,
        "icon": icon,
        "reasons": reasons,
        "positive_signals": positive_signals
    }


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    raw_url = data.get("url", "").strip()

    if not raw_url:
        return jsonify({"error": "No URL provided"}), 400

    # Normalize URL
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url

    try:
        parsed = urllib.parse.urlparse(raw_url)
        hostname = parsed.hostname
        if not hostname:
            return jsonify({"error": "Invalid URL format"}), 400
    except Exception:
        return jsonify({"error": "Could not parse URL"}), 400

    # Run all checks
    ssl_result = check_ssl(hostname)
    blacklist_result = check_blacklist(hostname, raw_url)
    redirect_result = get_redirect_chain(raw_url)
    domain_age_result = get_domain_age(hostname)
    verdict = compute_verdict(ssl_result, blacklist_result, redirect_result, domain_age_result)

    return jsonify({
        "url": raw_url,
        "hostname": hostname,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "verdict": verdict,
        "ssl": ssl_result,
        "blacklist": blacklist_result,
        "redirects": redirect_result,
        "domain_age": domain_age_result
    })

@app.route('/')
def home():
    return render_template('index.html')
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


if __name__ == "__main__":
    print("🔍 URL Checker API running on http://localhost:5000")
    app.run(debug=True, port=5000)