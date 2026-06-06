import requests
import urllib3
urllib3.disable_warnings()

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "medium",
        "desc": "HSTS not set. Browser may connect over HTTP. Enables downgrade attacks.",
        "cwe": "CWE-319",
        "rec": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "severity": "medium",
        "desc": "No CSP defined. XSS attacks not mitigated at the header level.",
        "cwe": "CWE-1021",
        "rec": "Define a strict Content-Security-Policy header."
    },
    "X-Frame-Options": {
        "severity": "medium",
        "desc": "X-Frame-Options missing. Clickjacking attacks are possible.",
        "cwe": "CWE-1021",
        "rec": "Add: X-Frame-Options: DENY or SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "low",
        "desc": "MIME-type sniffing possible. Browser may misinterpret file types.",
        "cwe": "CWE-16",
        "rec": "Add: X-Content-Type-Options: nosniff"
    },
    "Referrer-Policy": {
        "severity": "low",
        "desc": "No Referrer-Policy set. Full URL may leak to third parties.",
        "cwe": "CWE-200",
        "rec": "Add: Referrer-Policy: strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "severity": "low",
        "desc": "Permissions-Policy missing. Browser features not restricted.",
        "cwe": "CWE-16",
        "rec": "Add Permissions-Policy to restrict camera, mic, geolocation."
    },
    "X-XSS-Protection": {
        "severity": "low",
        "desc": "X-XSS-Protection header absent. Legacy XSS filter not enabled.",
        "cwe": "CWE-79",
        "rec": "Add: X-XSS-Protection: 1; mode=block"
    },
}

INFO_LEAK_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]

def run(target):
    findings = []
    logs = []

    if not target.startswith("http"):
        target = "https://" + target

    logs.append({"type":"info","msg":f"Fetching headers from {target}"})

    try:
        resp = requests.get(target, timeout=10, verify=False, allow_redirects=True)
        headers = resp.headers
        logs.append({"type":"ok","msg":f"Response: HTTP {resp.status_code}"})
    except requests.exceptions.SSLError:
        try:
            resp = requests.get(target.replace("https://","http://"), timeout=10, verify=False)
            headers = resp.headers
            logs.append({"type":"warn","msg":"SSL error — fell back to HTTP"})
        except Exception as e:
            logs.append({"type":"err","msg":f"Connection failed: {e}"})
            return findings, logs
    except Exception as e:
        logs.append({"type":"err","msg":f"Request failed: {e}"})
        return findings, logs

    logs.append({"type":"info","msg":"Analyzing security headers..."})

    for header, meta in SECURITY_HEADERS.items():
        if header not in headers:
            logs.append({"type":"warn","msg":f"Missing: {header}"})
            findings.append({
                "severity": meta["severity"],
                "module": "Header Analyzer",
                "name": f"Missing Header: {header}",
                "description": meta["desc"],
                "reference": meta["cwe"],
                "detail": f"Recommendation: {meta['rec']}"
            })
        else:
            logs.append({"type":"ok","msg":f"Present: {header}"})

    # Info disclosure
    for h in INFO_LEAK_HEADERS:
        if h in headers:
            val = headers[h]
            logs.append({"type":"warn","msg":f"Information disclosure: {h}: {val}"})
            findings.append({
                "severity": "low",
                "module": "Header Analyzer",
                "name": f"Server Info Disclosure: {h}",
                "description": f"Header '{h}' reveals: {val}. Attackers can fingerprint the server.",
                "reference": "CWE-200",
                "detail": f"Remove or obfuscate the {h} response header."
            })

    # Cookie flags
    cookies = resp.cookies
    for cookie in cookies:
        issues = []
        if not cookie.secure:
            issues.append("missing Secure flag")
        if not cookie.has_nonstandard_attr("HttpOnly"):
            issues.append("missing HttpOnly flag")
        if issues:
            logs.append({"type":"warn","msg":f"Cookie '{cookie.name}': {', '.join(issues)}"})
            findings.append({
                "severity": "medium",
                "module": "Header Analyzer",
                "name": f"Insecure Cookie: {cookie.name}",
                "description": f"Cookie is {', '.join(issues)}. Risk of session hijacking via XSS or network sniffing.",
                "reference": "CWE-614",
                "detail": "Set Secure and HttpOnly flags on all session cookies."
            })

    logs.append({"type":"ok","msg":f"Header analysis complete. {len(findings)} issues found."})
    return findings, logs
