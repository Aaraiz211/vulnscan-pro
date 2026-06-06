import requests
import concurrent.futures
import urllib3
urllib3.disable_warnings()

COMMON_PATHS = [
    "/admin", "/administrator", "/admin.php", "/admin/login",
    "/login", "/signin", "/dashboard", "/portal",
    "/.env", "/.env.local", "/.env.backup",
    "/config.php", "/config.json", "/config.yml", "/configuration.php",
    "/backup.zip", "/backup.tar.gz", "/backup.sql", "/db.sql",
    "/phpinfo.php", "/info.php", "/test.php",
    "/robots.txt", "/sitemap.xml", "/.htaccess", "/.gitignore",
    "/.git/config", "/.git/HEAD",
    "/wp-admin", "/wp-login.php", "/wp-config.php",
    "/upload", "/uploads", "/files", "/static",
    "/api", "/api/v1", "/api/docs", "/swagger", "/swagger-ui.html",
    "/actuator", "/actuator/health", "/actuator/env",
    "/server-status", "/server-info",
    "/phpmyadmin", "/pma", "/myadmin",
]

SEVERITY_MAP = {
    "/.env": ("critical", "CWE-312", "Environment file may expose DB credentials, API keys, and secrets."),
    "/.env.local": ("critical", "CWE-312", "Local environment file exposed. May contain sensitive credentials."),
    "/.env.backup": ("critical", "CWE-312", "Backup environment file publicly accessible."),
    "/.git/config": ("critical", "CWE-538", "Git config exposed. Source code repository may be downloadable."),
    "/.git/HEAD": ("critical", "CWE-538", "Git repository structure exposed. Source code leak risk."),
    "/config.php": ("high", "CWE-312", "Config file exposed. May contain DB credentials."),
    "/config.json": ("high", "CWE-312", "JSON config file accessible. May contain API keys or secrets."),
    "/wp-config.php": ("critical", "CWE-312", "WordPress config exposed. DB credentials at risk."),
    "/backup.zip": ("high", "CWE-538", "Backup archive accessible. May contain full source code."),
    "/backup.sql": ("critical", "CWE-538", "SQL backup file exposed. Full database dump may be downloadable."),
    "/db.sql": ("critical", "CWE-538", "SQL dump file accessible. Database contents exposed."),
    "/phpinfo.php": ("high", "CWE-200", "phpinfo() page exposes PHP config, server paths, and env variables."),
    "/admin": ("medium", "CWE-284", "Admin panel accessible. Verify authentication is enforced."),
    "/wp-admin": ("medium", "CWE-284", "WordPress admin panel exposed."),
    "/phpmyadmin": ("high", "CWE-284", "phpMyAdmin exposed. Direct DB management interface accessible."),
    "/actuator/env": ("high", "CWE-200", "Spring Boot actuator env endpoint exposed. Config/secrets leak."),
    "/actuator": ("medium", "CWE-284", "Spring Boot actuator exposed. May leak internal application data."),
    "/swagger-ui.html": ("info", "CWE-16", "Swagger UI exposed. Full API schema publicly documented."),
    "/api/docs": ("info", "CWE-16", "API documentation publicly accessible."),
    "/.htaccess": ("medium", "CWE-538", ".htaccess file readable. Server config may be exposed."),
    "/server-status": ("medium", "CWE-200", "Apache server-status page exposed. Reveals active connections."),
}

def check_path(base_url, path, session):
    url = base_url.rstrip("/") + path
    try:
        r = session.get(url, timeout=6, allow_redirects=False, verify=False)
        if r.status_code in (200, 301, 302, 403):
            return path, r.status_code, len(r.content)
        return path, None, 0
    except:
        return path, None, 0

def run(target):
    findings = []
    logs = []

    if not target.startswith("http"):
        target = "https://" + target

    base = target.rstrip("/")
    logs.append({"type":"info","msg":f"Enumerating {len(COMMON_PATHS)} common paths on {base}"})

    session = requests.Session()
    session.headers["User-Agent"] = "VulnScanPro/1.0 (Authorized Security Scanner)"

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        futures = {ex.submit(check_path, base, path, session): path for path in COMMON_PATHS}
        for future in concurrent.futures.as_completed(futures):
            path, status, size = future.result()
            if status:
                found.append((path, status, size))

    found.sort(key=lambda x: x[0])
    logs.append({"type":"ok","msg":f"Enumeration complete. {len(found)} paths responded."})

    for path, status, size in found:
        meta = SEVERITY_MAP.get(path)
        if meta:
            sev, cwe, desc = meta
        else:
            if status == 403:
                sev, cwe, desc = "low", "CWE-284", f"Path {path} returns 403 Forbidden. Resource exists but access restricted."
            else:
                sev, cwe, desc = "info", "CWE-16", f"Path {path} accessible (HTTP {status})."

        status_label = f"HTTP {status}"
        log_type = "err" if sev == "critical" else "warn" if sev == "high" else "ok"
        logs.append({"type": log_type, "msg": f"[{status_label}] {path} — {sev.upper()}"})

        findings.append({
            "severity": sev,
            "module": "Dir Enumeration",
            "name": f"Exposed Path: {path}",
            "description": desc,
            "reference": cwe,
            "detail": f"URL: {base}{path} | Status: {status_label} | Size: {size} bytes"
        })

    return findings, logs
