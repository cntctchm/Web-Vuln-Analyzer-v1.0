# vuln_cli.py
# Terminal UI for Ultimate Web Vuln Analyzer (Rich)
# - menu, batch, history, detailed display
# Author: cntctchm

import json
from pathlib import Path
from datetime import datetime
from statistics import mean
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Prompt
from rich import box

from analyzer.scanner import (
    full_scan, normalize_url, compute_security_score,
    save_json_report, generate_html_report, REPORT_DIR, TIMEOUT, get_history
)

console = Console()
REPORT_DIR = Path(REPORT_DIR)

def header_table(report):
    headers = report.get("headers", {}) or {}
    t = Table(show_header=False, box=box.SIMPLE)
    t.add_column("Item", style="cyan", no_wrap=True, width=30)
    t.add_column("Value", style="magenta")
    t.add_row("Target", report.get("target", "-"))
    t.add_row("Status code", str(headers.get("status_code", "-")))
    t.add_row("Server", str(headers.get("server", "-")))
    https_field = report.get("https")
    https_val = https_field.get("https") if isinstance(https_field, dict) else bool(https_field)
    t.add_row("HTTPS", str(https_val))
    for h in ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"]:
        val = headers.get(h)
        t.add_row(h, str(val) if val else "[red]MISSING[/red]")
    return t

def show_cookies(report):
    cookies = report.get("cookies", []) or []
    if not cookies:
        console.print(Panel("Aucun cookie détecté.", title="Cookies", style="yellow"))
        return
    tab = Table(title="Cookies", box=box.MINIMAL)
    tab.add_column("Name", width=20)
    tab.add_column("Secure", width=6)
    tab.add_column("HttpOnly", width=8)
    tab.add_column("SameSite", width=10)
    tab.add_column("Expires", overflow="fold")
    for c in cookies:
        tab.add_row(c.get("name","-"), str(bool(c.get("secure"))), str(bool(c.get("httponly"))), str(c.get("samesite") or "-"), str(c.get("expires") or "-"))
    console.print(tab)

def show_forms(report):
    forms = report.get("forms", []) or []
    if not forms:
        console.print(Panel("Aucun formulaire détecté.", title="Formulaires", style="yellow"))
        return
    tab = Table(title="Formulaires détectés", box=box.MINIMAL_DOUBLE_HEAD)
    tab.add_column("#", width=3)
    tab.add_column("Action", overflow="fold")
    tab.add_column("Method", width=8)
    tab.add_column("Inputs", overflow="fold")
    for i, f in enumerate(forms, start=1):
        inputs = ", ".join(f"{inp.get('name','-')}:{inp.get('type','-')}" for inp in f.get("inputs", [])) or "-"
        insecure = " ⚠️" if f.get("insecure_password_field") else ""
        csrf = "" if f.get("has_csrf") else " (no CSRF token)"
        tab.add_row(str(i), f.get("action","-"), f.get("method","-"), inputs + insecure + csrf)
    console.print(tab)

def show_passive(report):
    passive = report.get("passive", {})
    if not passive:
        console.print(Panel("Aucun indicateur passif détecté.", title="Passive", style="yellow"))
        return
    tab = Table(title="Passive Indicators", box=box.MINIMAL)
    tab.add_column("Type"); tab.add_column("Value", overflow="fold")
    tab.add_row("SQL errors found", str(passive.get("sql_error_found")))
    tab.add_row("XSS indicators", str(passive.get("xss_indicators")))
    refl = passive.get("reflected_params") or []
    tab.add_row("Reflected params", str(refl or "-"))
    console.print(tab)

def list_reports():
    files = sorted(REPORT_DIR.glob("report_*.json"), key=lambda p:p.stat().st_mtime, reverse=True)
    if not files:
        console.print("[yellow]Aucun rapport trouvé.[/yellow]")
        return []
    tab = Table(title="Rapports disponibles", box=box.SIMPLE)
    tab.add_column("#", width=3)
    tab.add_column("Fichier")
    tab.add_column("Date", style="dim")
    for i,f in enumerate(files, start=1):
        dt = datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        tab.add_row(str(i), f.name, dt)
    console.print(tab)
    return files

def view_report(path):
    try:
        with path.open("r", encoding="utf-8") as fh:
            report = json.load(fh)
    except Exception as e:
        console.print(f"[red]Erreur lecture fichier:[/] {e}"); return
    console.rule(f"[bold cyan]Report — {report.get('target', path.name)}[/bold cyan]")
    console.print(header_table(report))
    sec = report.get("security_summary", {})
    score = sec.get("score", 0)
    color = "green" if score >= 80 else "yellow" if score >= 60 else "red"
    console.print(Panel(f"[bold]{score} / 100[/bold]\nIssues: {len(sec.get('issues', []))}", title="Security Score", style=color))
    if sec.get("suggestions"):
        console.print(Panel("\n".join(f"- {s}" for s in sec["suggestions"][:10]), title="Suggestions", style="cyan"))
    show_cookies(report)
    show_forms(report)
    show_passive(report)
    console.print("\nEnrichment:")
    enrich = report.get("enrichment", {})
    if enrich:
        etab = Table(box=box.SIMPLE)
        etab.add_column("Type"); etab.add_column("Value", overflow="fold")
        etab.add_row("DNS", str(enrich.get("dns",{})))
        etab.add_row("TLS", str(enrich.get("tls",{})))
        etab.add_row("Open ports", str(enrich.get("open_ports",[])))
        console.print(etab)

def run_single_scan():
    url = Prompt.ask("URL à scanner (ex: https://example.com)")
    if not url:
        console.print("[red]Aucune URL fournie[/red]"); return
    url = normalize_url(url)
    console.print(f"[cyan]Scanning {url} (timeout {TIMEOUT}s) — ceci peut prendre quelques secondes...[/cyan]")
    report = full_scan(url, mode="deep")
    if "security_summary" not in report:
        report["security_summary"] = compute_security_score(report)
    safe = url.replace("http://","").replace("https://","").replace("/","_")
    json_path = save_json_report(report, REPORT_DIR / f"report_{safe}.json")
    html_path = generate_html_report(report, REPORT_DIR / f"report_{safe}.html")
    console.print(f"[green]Report saved:[/] {json_path}")
    console.print(f"[green]HTML report:[/] {html_path}")
    view_report(Path(json_path))
    Prompt.ask("\nAppuyez sur Entrée pour revenir")

def run_batch():
    p = Prompt.ask("Fichier targets (une URL par ligne, ex: targets.txt)")
    path = Path(p)
    if not path.exists():
        console.print("[red]Fichier introuvable[/red]"); return
    targets = [l.strip() for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]
    console.print(f"[cyan]Batch mode — {len(targets)} targets[/cyan]")
    results = []
    for t in targets:
        console.print(f"\n[blue]Scanning {t}[/blue]")
        try:
            r = full_scan(t, mode="quick")
            if "security_summary" not in r:
                r["security_summary"] = compute_security_score(r)
            save_json_report(r, REPORT_DIR / f"report_{t.replace('http://','').replace('https://','').replace('/','_')}.json")
            results.append(r)
        except Exception as e:
            console.print(f"[red]Erreur sur {t}: {e}[/red]")
    # summary
    if results:
        scores = [r.get("security_summary",{}).get("score",0) for r in results]
        avg = mean(scores) if scores else 0
        worst = sorted(results, key=lambda x: x.get("security_summary",{}).get("score",0))[:3]
        console.print(Panel(f"Batch results — scanned {len(results)} targets\nAverage score: {avg:.1f}", title="Batch summary"))
        wtab = Table(title="Worst 3", box=box.SIMPLE)
        wtab.add_column("#", width=3); wtab.add_column("Target"); wtab.add_column("Score", width=6)
        for i,r in enumerate(worst, start=1):
            s = r.get("security_summary",{}).get("score",0)
            wtab.add_row(str(i), r.get("target","-"), str(s))
        console.print(wtab)
    Prompt.ask("\nAppuyez sur Entrée pour revenir")

def show_history():
    rows = get_history(30)
    if not rows:
        console.print("[yellow]Aucun historique[/yellow]"); return
    tab = Table(title="Scan History (last 30)", box=box.SIMPLE)
    tab.add_column("#", width=3)
    tab.add_column("Target")
    tab.add_column("Score", width=6)
    tab.add_column("Scanned at", style="dim")
    for i, r in enumerate(rows, start=1):
        tab.add_row(str(i), r[0], str(r[1]), r[2])
    console.print(tab)
    Prompt.ask("\nAppuyez sur Entrée pour revenir")

def main_menu():
    while True:
        console.clear()
        console.rule("[bold cyan]Web Vuln Analyzer — ULTIMATE (Terminal)[/bold cyan]")
        console.print(Panel("[green]Local execution only — scan only sites you own or have permission to test[/green]\n\nDeveloped by: [bold]cntctchm[/bold]"))
        console.print("1) Lancer un scan (URL)")
        console.print("2) Batch (targets.txt)")
        console.print("3) Lister les rapports")
        console.print("4) Voir un rapport")
        console.print("5) Historique (SQLite)")
        console.print("6) Quitter")
        choice = Prompt.ask("Choix", choices=["1","2","3","4","5","6"], default="1")
        if choice == "1":
            run_single_scan()
        elif choice == "2":
            run_batch()
        elif choice == "3":
            list_reports(); Prompt.ask("\nAppuyez sur Entrée pour revenir")
        elif choice == "4":
            files = list_reports()
            if not files: Prompt.ask("\nAppuyez sur Entrée pour revenir"); continue
            idx = Prompt.ask("N° du rapport à afficher (ou 'c' pour annuler)")
            if idx.lower()=="c": continue
            try:
                i = int(idx)-1
                if 0 <= i < len(files):
                    view_report(files[i])
                else:
                    console.print("[red]Index invalide[/red]")
            except:
                console.print("[red]Entrée invalide[/red]")
            Prompt.ask("\nAppuyez sur Entrée pour revenir")
        elif choice == "5":
            show_history()
        else:
            console.print("[red]Sortie...[/red]"); break

if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        console.print("\n[red]Interrompu par l'utilisateur[/red]")
