from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
import json, sys, os
sys.path.insert(0, os.path.dirname(__file__))

from modules import port_scanner, header_analyzer, ssl_checker, dir_enum, injection_detector, reporter

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

MODULE_MAP = {
    "port":      port_scanner,
    "header":    header_analyzer,
    "ssl":       ssl_checker,
    "dir":       dir_enum,
    "injection": injection_detector,
}

@app.route("/")
def index():
    return send_from_directory("templates", "index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json()
    target  = (data.get("target") or "").strip()
    modules = data.get("modules", list(MODULE_MAP.keys()))
    authorized = data.get("authorized", False)

    if not target:
        return jsonify({"error": "No target specified."}), 400
    if not authorized:
        return jsonify({"error": "Authorization not confirmed."}), 403

    all_findings = []
    all_logs     = []

    for mod_key in modules:
        mod = MODULE_MAP.get(mod_key)
        if not mod:
            continue
        try:
            findings, logs = mod.run(target)
            all_findings.extend(findings)
            all_logs.extend(logs)
        except Exception as e:
            all_logs.append({"type":"err","msg":f"Module {mod_key} error: {str(e)}"})

    scan_meta = {"modules": [m for m in modules if m in MODULE_MAP]}
    report_json = reporter.generate_json(target, all_findings, scan_meta)
    report_html = reporter.generate_html(target, all_findings, scan_meta)

    return jsonify({
        "findings":    all_findings,
        "logs":        all_logs,
        "report_json": report_json,
        "report_html": report_html,
    })

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "tool": "VulnScan Pro v1.0.0"})

if __name__ == "__main__":
    print("=" * 55)
    print("  VulnScan Pro v1.0.0")
    print("  Author : Aaraiz Tahir | Air University BS CYS")
    print("  For authorized penetration testing only.")
    print("=" * 55)
    print("  Starting server → http://127.0.0.1:5000")
    print("=" * 55)
    app.run(debug=False, host="127.0.0.1", port=5000)
