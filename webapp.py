import os, json
from flask import Flask, render_template_string

app = Flask(__name__)

TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <title>Web Vuln Analyzer - Reports</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; }
    pre { background:#f6f8fa; padding:12px; border-radius:6px; overflow:auto; }
    .report { border:1px solid #ddd; padding:12px; margin-bottom:16px; border-radius:8px; }
    h2 { margin-bottom:4px; }
  </style>
</head>
<body>
  <h1>Web Vuln Analyzer — Reports</h1>
  {% if reports %}
    {% for r in reports %}
      <div class="report">
        <h2>{{ r.url }}</h2>
        <h3>Headers</h3>
        <pre>{{ r.headers | tojson(indent=2) }}</pre>
        <h3>Forms</h3>
        <pre>{{ r.forms | tojson(indent=2) }}</pre>
        <h3>Cookies</h3>
        <pre>{{ r.cookies | tojson(indent=2) }}</pre>
      </div>
    {% endfor %}
  {% else %}
    <p>No reports found. Run <code>python check_site.py &lt;url&gt;</code> to create a report.</p>
  {% endif %}
</body>
</html>
"""

def load_reports():
    files = [f for f in os.listdir('.') if f.startswith("report_") and f.endswith(".json")]
    reports = []
    for f in sorted(files, reverse=True):
        try:
            with open(f, encoding="utf-8") as fh:
                r = json.load(fh)
                r["url"] = r.get("target", f.replace("report_","").replace(".json",""))
                reports.append(r)
        except Exception:
            continue
    return reports

@app.route("/")
def index():
    reports = load_reports()
    return render_template_string(TEMPLATE, reports=reports)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
