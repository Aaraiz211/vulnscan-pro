import socket
import concurrent.futures
from datetime import datetime

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
    9200: "Elasticsearch", 11211: "Memcached"
}

PORT_RISK = {
    21: ("high", "FTP transmits credentials in plaintext. Prefer SFTP.", "CWE-319"),
    22: ("low", "SSH exposed. Ensure key-based auth and disable root login.", "CWE-307"),
    23: ("critical", "Telnet is unencrypted. Disable immediately and use SSH.", "CWE-319"),
    25: ("medium", "SMTP exposed. Verify relay restrictions are in place.", "CWE-284"),
    53: ("info", "DNS service detected. Check for zone transfer vulnerability.", "CWE-16"),
    80: ("info", "HTTP service running. Unencrypted traffic possible.", "CWE-319"),
    110: ("medium", "POP3 exposed. May transmit credentials in cleartext.", "CWE-319"),
    143: ("medium", "IMAP exposed. Check for STARTTLS enforcement.", "CWE-319"),
    443: ("info", "HTTPS detected. Verify certificate and cipher configuration.", "CWE-295"),
    445: ("critical", "SMB exposed. Risk of EternalBlue and ransomware attacks.", "CWE-284"),
    3306: ("high", "MySQL port exposed to network. Risk of direct DB access.", "CWE-284"),
    3389: ("high", "RDP exposed. High-value target for brute force and BlueKeep.", "CWE-307"),
    5432: ("high", "PostgreSQL exposed. Should not be publicly accessible.", "CWE-284"),
    5900: ("high", "VNC exposed. Often has weak or no authentication.", "CWE-287"),
    6379: ("critical", "Redis exposed with no auth by default. Data theft risk.", "CWE-306"),
    8080: ("info", "Alternate HTTP port open. May expose dev/admin interfaces.", "CWE-284"),
    8443: ("info", "Alternate HTTPS port open.", "CWE-284"),
    27017: ("critical", "MongoDB exposed. Often unauthenticated. Full DB access risk.", "CWE-306"),
    9200: ("critical", "Elasticsearch exposed. Often unauthenticated. Data leak risk.", "CWE-306"),
    11211: ("high", "Memcached exposed. Can be abused for DDoS amplification.", "CWE-284"),
}

def scan_port(host, port, timeout=1.0):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port, result == 0
    except Exception:
        return port, False

def resolve_host(target):
    try:
        target = target.replace("https://","").replace("http://","").split("/")[0]
        ip = socket.gethostbyname(target)
        return target, ip
    except Exception as e:
        return target, None

def run(target):
    findings = []
    logs = []
    host, ip = resolve_host(target)

    if not ip:
        logs.append({"type":"err","msg":f"Could not resolve host: {host}"})
        return findings, logs

    logs.append({"type":"info","msg":f"Resolved {host} → {ip}"})
    logs.append({"type":"info","msg":f"Scanning {len(COMMON_PORTS)} common ports..."})

    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as ex:
        futures = {ex.submit(scan_port, ip, port): port for port in COMMON_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port, is_open = future.result()
            if is_open:
                open_ports.append(port)

    open_ports.sort()
    logs.append({"type":"ok","msg":f"Scan complete. {len(open_ports)} open ports found."})

    for port in open_ports:
        service = COMMON_PORTS.get(port, "Unknown")
        risk = PORT_RISK.get(port)
        if risk:
            sev, desc, cwe = risk
        else:
            sev, desc, cwe = "info", f"Port {port} open.", "CWE-284"

        logs.append({"type": "warn" if sev in ("high","critical") else "ok",
                     "msg": f"Open port: {port}/{service}"})
        findings.append({
            "severity": sev,
            "module": "Port Scanner",
            "name": f"Open Port: {port} ({service})",
            "description": desc,
            "reference": cwe,
            "detail": f"Host: {ip} | Port: {port} | Service: {service}"
        })

    if not open_ports:
        logs.append({"type":"info","msg":"No common ports found open."})

    return findings, logs
