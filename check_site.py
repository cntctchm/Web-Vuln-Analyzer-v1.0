import sys, json
from analyzer.scanner import full_scan
from analyzer.utils import normalize_url, domain_from_url

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_site.py <url>")
        sys.exit(1)
    url = normalize_url(sys.argv[1])
    print(f"[+] Scanning {url} ...")
    report = full_scan(url)
    fname = f"report_{domain_from_url(url).replace(':','_').replace('/','_')}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f"[+] Report saved: {fname}")

if __name__ == "__main__":
    main()
