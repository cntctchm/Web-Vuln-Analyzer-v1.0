# 🕷️ Web Vuln Analyzer — Terminal-Based Vulnerability Scanner

**Web Vuln Analyzer** est un outil en ligne de commande léger permettant de scanner rapidement un site web pour détecter les failles de sécurité les plus courantes (CSP manquante, HSTS, XSS, ports ouverts, etc.).

## 🚀 Fonctionnalités
- Analyse des en-têtes de sécurité (HSTS, CSP, X-Frame-Options…)
- Détection de ports ouverts (scan rapide)
- Vérification HTTPS / TLS
- Recherche d’indicateurs passifs (XSS, erreurs SQL, etc.)
- Rapport complet (JSON + HTML)
- Interface CLI claire et interactive
- Fonctionne sur Windows, Linux et macOS

## ⚙️ Installation
```bash
git clone https://github.com/<ton-user>/web-vuln-analyzer.git
cd web-vuln-analyzer
pip install -r requirements.txt
