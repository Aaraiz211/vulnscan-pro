import json
from datetime import datetime

SEV_ORDER = {"critical":0,"high":1,"medium":2,"low":3,"info":4}
SEV_COLOR = {"critical":"#ff8389","high":"#ff832b","medium":"#f1c21b","low":"#42be65","info":"#33b1ff"}
SEV_BG = {"critical":"rgba(218,30,40,0.15)","high":"rgba(255,131,43,0.15)","medium":"rgba(241,194,27,0.15)","low":"rgba(36,161,72,0.15)","info":"rgba(51,177,255,0.12)"}

def generate_json(target, findings, scan_meta):
    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"],0)+1
    return {
        "tool": "VulnScan Pro v1.0.0",
        "author": "Aaraiz Tahir | BS Cybersecurity — Air University",
        "disclaimer": "For authorized penetration testing only.",
        "target": target,
        "scan_date": datetime.utcnow().isoformat() + "Z",
        "modules_run": scan_meta.get("modules",[]),
        "summary": counts,
        "total_findings": len(findings),
        "findings": sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"],5))
    }

def generate_html(target, findings, scan_meta):
    counts = {"critical":0,"high":0,"medium":0,"low":0,"info":0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"],0)+1

    sorted_findings = sorted(findings, key=lambda x: SEV_ORDER.get(x["severity"],5))
    rows = ""
    for i, f in enumerate(sorted_findings):
        sev = f["severity"]
        rows += f"""
        <tr>
          <td style="font-family:monospace;color:#4d5a70">{str(i+1).zfill(3)}</td>
          <td><span style="background:{SEV_BG[sev]};color:{SEV_COLOR[sev]};padding:2px 8px;border-radius:2px;font-size:11px;font-weight:600;text-transform:uppercase;font-family:monospace">{sev}</span></td>
          <td style="color:#33b1ff;font-size:12px;font-family:monospace">{f['module']}</td>
          <td style="color:#f4f4f4;font-weight:500">{f['name']}</td>
          <td style="color:#a8b2c8;font-size:12px">{f['description']}</td>
          <td style="color:#08bdba;font-size:11px;font-family:monospace">{f['reference']}</td>
          <td style="color:#4d5a70;font-size:11px">{f.get('detail','')}</td>
        </tr>"""

    stat_cards = ""
    labels = [("Critical","critical"),("High","high"),("Medium","medium"),("Low","low"),("Info","info")]
    for label, key in labels:
        stat_cards += f"""
        <div style="background:#141c2e;border:1px solid #1e2d47;padding:16px 20px;border-radius:2px;text-align:center">
          <div style="font-size:10px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#4d5a70;margin-bottom:6px">{label}</div>
          <div style="font-size:26px;font-weight:300;font-family:monospace;color:{SEV_COLOR[key]}">{counts[key]}</div>
        </div>"""

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>VulnScan Pro — Report | {target}</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500&family=IBM+Plex+Sans:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
  body{{background:#0a0e1a;color:#f4f4f4;font-family:'IBM Plex Sans',sans-serif;margin:0;padding:0}}
  .topbar{{background:#060a14;border-bottom:1px solid #1e2d47;padding:12px 40px;display:flex;align-items:center;gap:16px}}
  .brand{{font-size:14px;font-weight:600;letter-spacing:.08em;color:#f4f4f4}}
  .brand span{{color:#33b1ff}}
  .container{{max-width:1200px;margin:0 auto;padding:32px 40px}}
  .section-title{{font-size:11px;font-weight:600;letter-spacing:.1em;text-transform:uppercase;color:#4d5a70;margin-bottom:12px}}
  table{{width:100%;border-collapse:collapse;font-size:12px;background:#0f1525;border:1px solid #1e2d47;border-radius:2px}}
  th{{background:#060a14;color:#4d5a70;padding:10px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.1em;border-bottom:1px solid #1e2d47}}
  td{{padding:10px 14px;border-bottom:1px solid #1e2d47;vertical-align:top;color:#a8b2c8}}
  tr:last-child td{{border-bottom:none}}
  tr:hover td{{background:#1a2540}}
  .footer{{margin-top:48px;padding:20px 0;border-top:1px solid #1e2d47;font-size:11px;color:#4d5a70;font-family:monospace;display:flex;justify-content:space-between}}
  @media print{{body{{background:#fff;color:#000}}}}
</style>
</head>
<body>
<div class="topbar">
  <div class="brand">VULNSCAN <span>PRO</span></div>
  <span style="color:#4d5a70;font-size:12px">|</span>
  <span style="color:#a8b2c8;font-size:12px">Penetration Test Report</span>
  <span style="margin-left:auto;font-size:11px;font-family:monospace;color:#4d5a70">{datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}</span>
</div>
<div class="container">
  <div style="margin-bottom:32px;padding-bottom:24px;border-bottom:1px solid #1e2d47">
    <div style="font-size:20px;font-weight:600;margin-bottom:4px">Vulnerability Assessment Report</div>
    <div style="font-size:13px;color:#a8b2c8;font-family:monospace">Target: {target}</div>
    <div style="font-size:12px;color:#4d5a70;margin-top:4px">Modules: {', '.join(scan_meta.get('modules',[]))}</div>
  </div>

  <div class="section-title">Executive Summary</div>
  <div style="display:grid;grid-template-columns:repeat(5,1fr);gap:1px;background:#1e2d47;border:1px solid #1e2d47;border-radius:2px;margin-bottom:32px;overflow:hidden">
    {stat_cards}
  </div>

  <div class="section-title">Findings ({len(findings)} total)</div>
  <table>
    <thead>
      <tr>
        <th>#</th><th>Severity</th><th>Module</th><th>Finding</th>
        <th>Description</th><th>Reference</th><th>Detail</th>
      </tr>
    </thead>
    <tbody>{rows}</tbody>
  </table>

  <div class="footer">
    <span>VulnScan Pro v1.0.0 | Author: Aaraiz Tahir | BS Cybersecurity — Air University</span>
    <span>For authorized penetration testing only</span>
  </div>
</div>
</body>
</html>"""
