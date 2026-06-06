import requests
from urllib.parse import urlparse, parse_qs, urljoin
from html.parser import HTMLParser
import urllib3
urllib3.disable_warnings()

class FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms = []
        self.current_form = None
        self.inputs = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.current_form = {
                "action": attrs.get("action",""),
                "method": attrs.get("method","GET").upper(),
                "inputs": []
            }
        elif tag == "input" and self.current_form is not None:
            self.current_form["inputs"].append({
                "name": attrs.get("name",""),
                "type": attrs.get("type","text"),
                "id": attrs.get("id","")
            })

    def handle_endtag(self, tag):
        if tag == "form" and self.current_form:
            self.forms.append(self.current_form)
            self.current_form = None

SQLI_RISK_INPUTS = ["id","user","username","email","search","query","q","keyword","name","pass","password","token","page","cat","category","product","item","order"]
XSS_RISK_INPUTS = ["search","q","query","name","comment","message","input","text","content","title","subject","username","email","url","redirect","next","ref","return"]

def run(target):
    findings = []
    logs = []

    if not target.startswith("http"):
        target = "https://" + target

    logs.append({"type":"info","msg":"Passively detecting injection points (no payloads sent)..."})
    logs.append({"type":"info","msg":f"Fetching page: {target}"})

    try:
        session = requests.Session()
        session.headers["User-Agent"] = "VulnScanPro/1.0 (Authorized Security Scanner)"
        resp = session.get(target, timeout=10, verify=False)
        html = resp.text
        logs.append({"type":"ok","msg":f"Page fetched. Size: {len(html)} bytes"})
    except Exception as e:
        logs.append({"type":"err","msg":f"Failed to fetch page: {e}"})
        return findings, logs

    # URL parameter analysis
    parsed = urlparse(target)
    params = parse_qs(parsed.query)
    if params:
        logs.append({"type":"info","msg":f"URL parameters found: {list(params.keys())}"})
        for param in params:
            pl = param.lower()
            if any(r in pl for r in SQLI_RISK_INPUTS):
                logs.append({"type":"warn","msg":f"Potential SQLi point — URL param: {param}"})
                findings.append({
                    "severity": "medium",
                    "module": "Injection Detector",
                    "name": f"Potential SQLi Point: URL param '{param}'",
                    "description": f"URL parameter '{param}' matches high-risk patterns for SQL injection. Manual testing with SQLMap recommended.",
                    "reference": "CWE-89",
                    "detail": f"URL: {target} | Parameter: {param} | Action: Test manually with: sqlmap -u \"{target}\" -p {param}"
                })
            if any(r in pl for r in XSS_RISK_INPUTS):
                logs.append({"type":"warn","msg":f"Potential XSS point — URL param: {param}"})
                findings.append({
                    "severity": "medium",
                    "module": "Injection Detector",
                    "name": f"Potential XSS Point: URL param '{param}'",
                    "description": f"URL parameter '{param}' is reflected in output without visible encoding. Manual XSS testing recommended.",
                    "reference": "CWE-79",
                    "detail": f"URL: {target} | Parameter: {param} | Action: Test with Burp Suite or manually."
                })
    else:
        logs.append({"type":"info","msg":"No URL parameters found on main page."})

    # Form analysis
    parser = FormParser()
    try:
        parser.feed(html)
    except:
        pass

    forms = parser.forms
    logs.append({"type":"info","msg":f"Found {len(forms)} form(s) on page."})

    for i, form in enumerate(forms):
        action = form.get("action","")
        method = form.get("method","GET")
        inputs = form.get("inputs",[])
        form_url = urljoin(target, action) if action else target

        input_names = [inp.get("name","") for inp in inputs if inp.get("name")]
        input_types = [inp.get("type","text") for inp in inputs]

        logs.append({"type":"info","msg":f"Form {i+1}: method={method}, action={form_url}, fields={input_names}"})

        has_password = any(t == "password" for t in input_types)
        if has_password and method == "GET":
            findings.append({
                "severity": "high",
                "module": "Injection Detector",
                "name": "Password Field in GET Form",
                "description": "Login form submits password via GET method. Credentials appear in URL and server logs.",
                "reference": "CWE-598",
                "detail": f"Form action: {form_url} | Change method to POST."
            })
            logs.append({"type":"err","msg":f"Form {i+1}: password field in GET form!"})

        for inp in inputs:
            name = inp.get("name","").lower()
            itype = inp.get("type","text")
            if itype in ("submit","button","hidden","file"):
                continue
            if any(r in name for r in SQLI_RISK_INPUTS):
                logs.append({"type":"warn","msg":f"Form {i+1}: Potential SQLi input field '{inp['name']}'"})
                findings.append({
                    "severity": "medium",
                    "module": "Injection Detector",
                    "name": f"Potential SQLi Field: '{inp['name']}' in Form {i+1}",
                    "description": f"Form field '{inp['name']}' matches common SQL injection patterns. Verify parameterized queries are used.",
                    "reference": "CWE-89",
                    "detail": f"Form: {form_url} | Field: {inp['name']} | Test with SQLMap or Burp Suite."
                })
            if any(r in name for r in XSS_RISK_INPUTS):
                logs.append({"type":"warn","msg":f"Form {i+1}: Potential XSS input field '{inp['name']}'"})
                findings.append({
                    "severity": "medium",
                    "module": "Injection Detector",
                    "name": f"Potential XSS Field: '{inp['name']}' in Form {i+1}",
                    "description": f"Form field '{inp['name']}' may reflect input in response. Verify output encoding is applied.",
                    "reference": "CWE-79",
                    "detail": f"Form: {form_url} | Field: {inp['name']} | Test with Burp Suite or OWASP ZAP."
                })

    # Inline JS source analysis for dangerous sinks
    import re
    dangerous_sinks = ["innerHTML","document.write","eval(","setTimeout(","setInterval("]
    for sink in dangerous_sinks:
        if sink in html:
            count = html.count(sink)
            logs.append({"type":"warn","msg":f"Dangerous JS sink found: {sink} ({count}x)"})
            findings.append({
                "severity": "low",
                "module": "Injection Detector",
                "name": f"Dangerous JS Sink: {sink}",
                "description": f"Source contains {count} use(s) of '{sink}'. If user input flows here without sanitization, DOM-based XSS is possible.",
                "reference": "CWE-79",
                "detail": f"Manually audit all uses of '{sink}' for unsanitized user input."
            })

    logs.append({"type":"ok","msg":f"Injection detection complete. {len(findings)} points flagged for manual review."})
    return findings, logs
