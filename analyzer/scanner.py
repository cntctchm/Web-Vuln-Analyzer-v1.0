# analyzer/scanner.py
# Ultimate passive Web Vuln Analyzer backend (terminal)
# - headers, cookies, forms analysis
# - passive detection XSS/SQLi indicators (NO intrusive payloads)
# - TLS basic checks, DNS lookup, light port probe
# - sensitive path probe (HEAD), batch-friendly
# - JSON/HTML report output
# - SQLite summary history (optional)
# Author: cntctchm
# Local, non-intrusive, for authorized testing only.

import re, json, time, socket, ssl, sqlite3
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, urljoin, parse_qs, unquote
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from bs4 import BeautifulSoup
from html import escape as html_escape

# -------- Config --------
TIMEOUT = 8
USER_AGENT = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
              "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/116 Safari/537.36")
HEADERS_TO_CHECK = [
    "Content-Security-Policy",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
]
SENSITIVE_PATHS = [
    "/.env", "/.git/config", "/.git/", "/admin", "/wp-admin",
    "/login", "/phpinfo.php", "/.htaccess", "/backup.zip", "/README.md",
    "/config.php", "/database.sql", "/.svn", "/web.config"
]
DEFAULT_PORTS = [21, 22, 25, 53, 80, 110, 143, 443, 445, 3306, 8080]
REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)
DB_FILE = Path("scan_history.db")

# -------- Helpers --------
def _session():
    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})
    return s

def normalize_url(u: str) -> str:
    if not u:
        return u
    u = u.strip()
    if not u.startswith(("http://", "https://")):
        u = "http://" + u
    return u.rstrip("/")

def safe_get(url, timeout=TIMEOUT):
    try:
        return _session().get(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def safe_head(url, timeout=TIMEOUT):
    try:
        return _session().head(url, timeout=timeout, allow_redirects=True)
    except Exception:
        return None

def collect_headers_from_history(response):
    acc = {}
    if not response:
        return acc
    for r in getattr(response, "history", []) + [response]:
        try:
            for k, v in r.headers.items():
                acc[k] = v
        except Exception:
            continue
    return acc

# -------- Header / Cookie / Form scanning --------
def scan_headers(target_url: str):
    r = safe_get(target_url)
    if r is None:
        return {"error": "request_failed"}
    combined = collect_headers_from_history(r)
    out = {h: combined.get(h) for h in HEADERS_TO_CHECK}
    out["server"] = combined.get("Server")
    out["set-cookie"] = combined.get("Set-Cookie")
    out["status_code"] = getattr(r, "status_code", None)
    out["url"] = getattr(r, "url", target_url)
    # try meta CSP
    if not out.get("Content-Security-Policy"):
        try:
            soup = BeautifulSoup(r.text or "", "html.parser")
            m = soup.find("meta", attrs={"http-equiv": lambda s: s and s.lower() == "content-security-policy"})
            if m and m.get("content"):
                out["Content-Security-Policy"] = m.get("content") + " (meta)"
        except Exception:
            pass
    return out

def parse_set_cookie(raw: str):
    if not raw:
        return []
    parts = re.split(r", (?=[^;=]+=[^;=]+;?)", raw)
    cookies = []
    for p in parts:
        p = p.strip()
        if not p:
            continue
        name = p.split("=", 1)[0].strip()
        secure = bool(re.search(r";\s*secure\b", p, re.I))
        httponly = bool(re.search(r";\s*httponly\b", p, re.I))
        samesite_m = re.search(r";\s*samesite\s*=\s*([^;]+)", p, re.I)
        samesite = samesite_m.group(1).strip() if samesite_m else None
        expires_m = re.search(r"expires=([^;]+)", p, re.I)
        expires = expires_m.group(1).strip() if expires_m else None
        cookies.append({"name": name, "raw": p, "secure": secure, "httponly": httponly, "samesite": samesite, "expires": expires})
    return cookies

def scan_forms(target_url: str):
    r = safe_get(target_url)
    if r is None:
        return []
    try:
        soup = BeautifulSoup(r.text or "", "html.parser")
    except Exception:
        return []
    out = []
    for f in soup.find_all("form"):
        action = f.get("action") or ""
        method = (f.get("method") or "get").upper()
        inputs = []
        for i in f.find_all(["input", "textarea", "select"]):
            itype = i.get("type", "text") if i.name == "input" else i.name
            iname = i.get("name") or i.get("id") or ""
            inputs.append({"name": iname, "type": itype})
        has_csrf = any("csrf" in (inp.get("name","").lower()) or "token" in (inp.get("name","").lower()) for inp in inputs)
        insecure_pw_field = any(inp.get("type","").lower() != "password" and "pass" in (inp.get("name","") or "").lower() for inp in inputs)
        out.append({
            "action": urljoin(r.url, action) if getattr(r,"url",None) else action,
            "method": method,
            "inputs": inputs,
            "has_csrf": has_csrf,
            "insecure_password_field": insecure_pw_field
        })
    return out

# -------- Passive indicators (non-intrusive) --------
SQL_PATTERNS = [r"you have an error in your sql syntax", r"warning: mysql", r"sqlstate", r"unclosed quotation mark", r"pg_query\("]
XSS_PATTERNS = [r"<script\b", r"on\w+\s*=", r"document\.cookie"]

def detect_sql_errors(text: str) -> bool:
    t = (text or "").lower()
    for p in SQL_PATTERNS:
        if re.search(p, t):
            return True
    return False

def detect_xss_indicators(text: str) -> bool:
    t = (text or "").lower()
    for p in XSS_PATTERNS:
        if re.search(p, t):
            return True
    return False

def detect_reflected_params(url: str, text: str):
    try:
        parsed = urlparse(url)
        q = parse_qs(parsed.query)
        reflected = []
        for k, vals in q.items():
            for v in vals:
                vclean = unquote(v).strip()
                if vclean and vclean in (text or ""):
                    reflected.append({"param": k, "value": vclean})
        return reflected
    except Exception:
        return []

# -------- TLS / DNS / Ports (light) --------
def dns_lookup(hostname: str):
    try:
        ip = socket.gethostbyname(hostname)
        return {"hostname": hostname, "ip": ip}
    except Exception as e:
        return {"error": str(e)}

def tls_basic_check(hostname: str, port=443, timeout=6):
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ss:
                cert = ss.getpeercert()
                return {"notAfter": cert.get("notAfter"), "subject": cert.get("subject"), "issuer": cert.get("issuer")}
    except Exception as e:
        return {"error": str(e)}

def probe_port(host: str, port: int, timeout=0.8):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        res = s.connect_ex((host, port))
        s.close()
        return port if res == 0 else None
    except:
        return None

def probe_ports(host: str, ports=None, workers=12):
    ports = ports or DEFAULT_PORTS
    open_ports = []
    with ThreadPoolExecutor(max_workers=min(workers, len(ports))) as ex:
        futures = {ex.submit(probe_port, host, p): p for p in ports}
        for f in as_completed(futures):
            try:
                p = f.result()
                if p:
                    open_ports.append(p)
            except:
                pass
    return sorted(open_ports)

# -------- Sensitive paths --------
def probe_sensitive_paths(base_url: str, workers=12):
    found = []
    base = base_url.rstrip("/")
    session = _session()
    def check(p):
        url = base + p
        try:
            r = session.head(url, timeout=3, allow_redirects=True)
            if r is None:
                return None
            if r.status_code == 200:
                return {"path": p, "status": 200}
            if r.status_code in (401, 403):
                return {"path": p, "status": r.status_code, "protected": True}
        except:
            return None
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(check, p): p for p in SENSITIVE_PATHS}
        for f in as_completed(futures):
            res = f.result()
            if res:
                found.append(res)
    return found

# -------- Fingerprinting hints --------
CVE_HINTS = {"apache/2.4.49": ["CVE-2021-41773"], "nginx/1.22.1": ["example-CVE"]}
def fingerprint(response):
    html = ""
    try:
        html = response.text or ""
    except:
        html = ""
    txt = (html or "").lower()
    cms = None
    if "/wp-content/" in txt or "wp-includes" in txt:
        cms = "wordpress"
    elif "cdn.shopify" in txt or "content=\"shopify" in txt:
        cms = "shopify"
    gen = None
    m = re.search(r'<meta name=["\']generator["\'] content=["\']([^"\']+)', html or "", re.I)
    if m:
        gen = m.group(1)
    server = None
    try:
        server = response.headers.get("Server") if response is not None else None
    except:
        server = None
    cves = []
    if server:
        sb = server.lower()
        for k, v in CVE_HINTS.items():
            if k in sb:
                cves.extend(v)
    return {"cms": cms, "generator": gen, "server": server, "cve_hints": cves}

# -------- Scoring & enrichment --------
def compute_security_score(report: dict):
    score = 100
    issues = []
    suggestions = []
    def penal(n, reason, p, suggestion=None):
        nonlocal score
        score -= p
        issues.append(f"{n}: {reason}")
        if suggestion:
            suggestions.append(suggestion)
    headers = report.get("headers") or {}
    # Headers
    if not headers.get("Strict-Transport-Security"):
        penal("HSTS", "missing", 15, "Add Strict-Transport-Security header")
    if not headers.get("Content-Security-Policy"):
        penal("CSP", "missing", 25, "Add Content-Security-Policy (start report-only)")
    if not headers.get("X-Frame-Options") and "frame-ancestors" not in (headers.get("Content-Security-Policy") or ""):
        penal("X-Frame-Options", "missing", 10, "Add X-Frame-Options or frame-ancestors in CSP")
    if (headers.get("X-Content-Type-Options") or "").lower() != "nosniff":
        penal("X-Content-Type-Options", "not 'nosniff'", 8, "Set X-Content-Type-Options: nosniff")
    if not headers.get("Referrer-Policy"):
        penal("Referrer-Policy", "missing", 4, "Set Referrer-Policy")
    # Cookies
    for c in report.get("cookies", []) or []:
        if not c.get("secure"):
            penal("Cookie Secure", c.get("name"), 5, "Set Secure on cookie")
        if not c.get("httponly"):
            penal("Cookie HttpOnly", c.get("name"), 5, "Set HttpOnly on cookie")
        if not c.get("samesite"):
            penal("Cookie SameSite", c.get("name"), 3, "Set SameSite on cookie")
    # Forms
    for f in report.get("forms", []) or []:
        if not f.get("has_csrf"):
            penal("Form CSRF", f.get("action"), 6, "Add CSRF tokens to forms")
        if f.get("insecure_password_field"):
            penal("Password field", f.get("action"), 6, "Use input type=password")
    # Passive detections
    if report.get("passive", {}).get("sql_error_found"):
        penal("SQL errors", "SQL error strings found", 25, "Sanitize DB queries / use parameterized queries")
    if report.get("passive", {}).get("xss_indicators"):
        penal("XSS indicators", "inline scripts or suspicious attributes", 12, "Avoid inline JS / use CSP with nonces")
    reflected = report.get("passive", {}).get("reflected_params") or []
    if reflected:
        penal("Reflected input", f"{len(reflected)} param(s) reflected", min(20, 5 * len(reflected)), "Sanitize & encode output")
    # Sensitive paths
    for p in report.get("enrichment", {}).get("sensitive_paths", []) or []:
        if p.get("status") == 200:
            penal("Sensitive path", p.get("path"), 15, f"Protect or remove {p.get('path')}")
    # TLS
    parsed = urlparse(report.get("target",""))
    if parsed.scheme == "http":
        penal("TLS", "http only", 20, "Enable HTTPS")
    score = max(0, min(100, score))
    return {"score": score, "issues": issues, "suggestions": list(dict.fromkeys(suggestions))}

# -------- SQLite history --------
def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT,
            score INTEGER,
            scanned_at TEXT,
            report_path TEXT
        )""")
        conn.commit()
        conn.close()
    except Exception:
        pass

def save_summary_to_db(target, score, report_path):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("INSERT INTO scans (target, score, scanned_at, report_path) VALUES (?, ?, ?, ?)",
                    (target, int(score), datetime.utcnow().isoformat(), str(report_path)))
        conn.commit()
        conn.close()
    except Exception:
        pass

def get_history(limit=20):
    try:
        conn = sqlite3.connect(DB_FILE)
        cur = conn.cursor()
        cur.execute("SELECT target, score, scanned_at, report_path FROM scans ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows
    except Exception:
        return []

# -------- Enrichment & main scan --------
def enrich_report(report: dict, mode="deep"):
    parsed = urlparse(report.get("target",""))
    host = parsed.hostname
    report.setdefault("enrichment", {})
    report["enrichment"]["dns"] = dns_lookup(host) if host else {"error":"no_host"}
    report["enrichment"]["tls"] = tls_basic_check(host) if host else {"error":"no_host"}
    resp = safe_get(report.get("target",""))
    report["enrichment"]["fingerprint"] = fingerprint(resp) if resp is not None else {}
    if mode == "deep":
        report["enrichment"]["sensitive_paths"] = probe_sensitive_paths(report.get("target",""))
        report["enrichment"]["open_ports"] = probe_ports(host, ports=DEFAULT_PORTS[:8], workers=12) if host else []
    else:
        report["enrichment"]["sensitive_paths"] = []
        report["enrichment"]["open_ports"] = []
    return report

def full_scan(target_url: str, mode: str = "deep"):
    target_url = normalize_url(target_url)
    init_db()  # ensure db exists
    report = {"target": target_url, "scanned_at": datetime.utcnow().isoformat()}
    headers = scan_headers(target_url)
    report["headers"] = headers
    report["forms"] = scan_forms(target_url)
    report["cookies"] = parse_set_cookie(headers.get("set-cookie") if isinstance(headers, dict) else None)
    report["https"] = {"https": normalize_url(target_url).startswith("https://")}
    # passive checks using final response
    resp = safe_get(target_url)
    report["passive"] = {}
    if resp is not None:
        text = resp.text or ""
        report["passive"]["sql_error_found"] = detect_sql_errors(text)
        report["passive"]["xss_indicators"] = detect_xss_indicators(text)
        report["passive"]["reflected_params"] = detect_reflected_params(target_url, text)
    else:
        report["passive"]["sql_error_found"] = False
        report["passive"]["xss_indicators"] = False
        report["passive"]["reflected_params"] = []
    report = enrich_report(report, mode=mode)
    report["security_summary"] = compute_security_score(report)
    # save summary to sqlite
    try:
        save_summary_to_db(report.get("target",""), report["security_summary"]["score"], "")
    except Exception:
        pass
    return report

# -------- Reporting utilities --------
def save_json_report(report: dict, outpath: Path = None):
    outpath = outpath or REPORT_DIR / f"report_{int(time.time())}.json"
    with open(outpath, "w", encoding="utf-8") as fh:
        json.dump(report, fh, indent=2, ensure_ascii=False)
    return str(outpath)

def generate_html_report(report: dict, outpath: Path = None):
    outpath = outpath or REPORT_DIR / f"report_{int(time.time())}.html"
    sec = report.get("security_summary", {})
    html = "<html><head><meta charset='utf-8'><title>Scan report</title></head><body>"
    html += f"<h1>Scan — {html_escape(report.get('target',''))}</h1>"
    html += f"<p>Score: {sec.get('score','n/a')} / 100</p>"
    html += "<h2>Suggestions</h2><ul>"
    for s in sec.get("suggestions", []):
        html += f"<li>{html_escape(s)}</li>"
    html += "</ul><h3>Headers</h3><table border='1'>"
    for k, v in (report.get("headers") or {}).items():
        html += f"<tr><td>{html_escape(str(k))}</td><td>{html_escape(str(v))}</td></tr>"
    html += "</table></body></html>"
    with open(outpath, "w", encoding="utf-8") as fh:
        fh.write(html)
    return str(outpath)

# small helpers for external import
init_db()
