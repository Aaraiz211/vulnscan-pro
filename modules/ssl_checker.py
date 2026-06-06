import ssl
import socket
import datetime
import requests
import urllib3
urllib3.disable_warnings()

def get_cert_info(host, port=443):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
                return cert, protocol, cipher, None
    except Exception as e:
        return None, None, None, str(e)

def check_tls_version(host, port, version_const, label):
    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = version_const
        ctx.maximum_version = version_const
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                return True
    except:
        return False

WEAK_CIPHERS = ["RC4","DES","3DES","NULL","EXPORT","MD5","anon"]

def run(target):
    findings = []
    logs = []

    host = target.replace("https://","").replace("http://","").split("/")[0].split(":")[0]
    port = 443

    logs.append({"type":"info","msg":f"Connecting to {host}:{port} for TLS inspection..."})

    cert, protocol, cipher, err = get_cert_info(host, port)

    if err and not cert:
        logs.append({"type":"err","msg":f"Could not connect for SSL check: {err}"})
        findings.append({
            "severity": "high",
            "module": "SSL/TLS Checker",
            "name": "No HTTPS / SSL Connection Failed",
            "description": f"Could not establish SSL connection: {err}. Site may not support HTTPS.",
            "reference": "CWE-319",
            "detail": "Ensure HTTPS is configured with a valid certificate."
        })
        return findings, logs

    # Certificate validity
    if cert:
        not_after = cert.get("notAfter","")
        not_before = cert.get("notBefore","")
        subject = dict(x[0] for x in cert.get("subject",[]))
        issuer = dict(x[0] for x in cert.get("issuer",[]))

        logs.append({"type":"ok","msg":f"Certificate issuer: {issuer.get('organizationName','Unknown')}"})
        logs.append({"type":"ok","msg":f"Subject CN: {subject.get('commonName','Unknown')}"})

        # Expiry check
        if not_after:
            try:
                expiry = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                logs.append({"type":"ok" if days_left > 30 else "warn","msg":f"Certificate expires in {days_left} days ({not_after})"})
                if days_left < 0:
                    findings.append({
                        "severity": "critical",
                        "module": "SSL/TLS Checker",
                        "name": "Certificate Expired",
                        "description": f"SSL certificate expired {abs(days_left)} days ago. Browsers will show security warnings.",
                        "reference": "CWE-298",
                        "detail": f"Expired: {not_after}"
                    })
                elif days_left < 15:
                    findings.append({
                        "severity": "high",
                        "module": "SSL/TLS Checker",
                        "name": "Certificate Expiring Soon",
                        "description": f"Certificate expires in {days_left} days. Renew immediately.",
                        "reference": "CWE-298",
                        "detail": f"Expiry: {not_after}"
                    })
                elif days_left < 30:
                    findings.append({
                        "severity": "medium",
                        "module": "SSL/TLS Checker",
                        "name": "Certificate Expiry Warning",
                        "description": f"Certificate expires in {days_left} days. Plan renewal.",
                        "reference": "CWE-298",
                        "detail": f"Expiry: {not_after}"
                    })
            except:
                pass

        # Self-signed check
        if subject.get("organizationName") == issuer.get("organizationName") and subject == issuer:
            logs.append({"type":"warn","msg":"Self-signed certificate detected"})
            findings.append({
                "severity": "high",
                "module": "SSL/TLS Checker",
                "name": "Self-Signed Certificate",
                "description": "Certificate is self-signed and not trusted by browsers. MitM risk.",
                "reference": "CWE-295",
                "detail": f"Subject: {subject} | Issuer: {issuer}"
            })

    # Protocol version
    if protocol:
        logs.append({"type":"ok","msg":f"Negotiated protocol: {protocol}"})
        if protocol in ("TLSv1","TLSv1.1","SSLv2","SSLv3"):
            findings.append({
                "severity": "high",
                "module": "SSL/TLS Checker",
                "name": f"Weak Protocol: {protocol}",
                "description": f"{protocol} is deprecated and vulnerable to POODLE/BEAST attacks.",
                "reference": "CWE-326",
                "detail": "Disable TLS 1.0 and 1.1. Use TLS 1.2 minimum, prefer TLS 1.3."
            })

    # Cipher check
    if cipher:
        cipher_name = cipher[0]
        logs.append({"type":"ok","msg":f"Negotiated cipher: {cipher_name}"})
        for weak in WEAK_CIPHERS:
            if weak in cipher_name.upper():
                findings.append({
                    "severity": "high",
                    "module": "SSL/TLS Checker",
                    "name": f"Weak Cipher Suite: {cipher_name}",
                    "description": f"Cipher {cipher_name} is considered cryptographically weak.",
                    "reference": "CWE-327",
                    "detail": "Use AES-256-GCM or CHACHA20-POLY1305 cipher suites."
                })
                break

    # HSTS check
    try:
        r = requests.get(f"https://{host}", timeout=8, verify=False)
        if "Strict-Transport-Security" not in r.headers:
            logs.append({"type":"warn","msg":"HSTS header not found"})
            findings.append({
                "severity": "medium",
                "module": "SSL/TLS Checker",
                "name": "HSTS Not Enforced",
                "description": "HTTP Strict Transport Security header missing. Downgrade attacks possible.",
                "reference": "CWE-319",
                "detail": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"
            })
        else:
            logs.append({"type":"ok","msg":"HSTS header present"})
    except:
        pass

    if not findings:
        logs.append({"type":"ok","msg":"SSL/TLS configuration looks good."})
    else:
        logs.append({"type":"ok","msg":f"SSL/TLS check complete. {len(findings)} issues found."})

    return findings, logs
