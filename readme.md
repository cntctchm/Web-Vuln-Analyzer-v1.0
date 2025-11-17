# Web Vuln Analyzer — CLI Web Vulnerability Scanner

**Web Vuln Analyzer** is a command-line tool for people who need to check a website for obvious security issues without pretending it’s anything more than that.
It scans, it reports, and that’s about it.

## 🚀 Fonctionnalités
- Looks at basic security headers (HSTS, CSP, X-Frame-Options, etc.)
- Quick open-port detection (don’t expect miracles)
- VChecks HTTPS/TLS setup
- Passive indicators of common issues (XSS hints, SQL error leakage, whatever shows itself)
- Exports a report in JSON and HTML
- CLI interface with no unnecessary nonsense
- FWorks on Windows, Linux, and macOS

## ⚙️ Installation
```bash
git clone https://github.com/<ton-user>/web-vuln-analyzer.git
cd web-vuln-analyzer
pip install -r requirements.txt
