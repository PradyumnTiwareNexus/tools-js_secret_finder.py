# 🔍 ReconNexus Tools Suite

A powerful collection of **Bug Bounty & Reconnaissance utilities** designed to automate passive & semi-passive discovery:

✔ JavaScript Secret Finder (async + heuristics)
✔ HTTP Header Scanner (tech + security fingerprinting)
✔ Wayback URL Miner (advanced CDX filtering)

This suite lives inside **`tools-js_secret_finder.py` repository** but contains **three full tools**, each focused on a different part of recon.

<p align="center">
  <img src="./PradyumnTiwareNexus.png" width="55%" />
</p>

---

# ⚠️ Legal Notice

These tools are made only for **authorized bug bounty testing**, **self-owned assets**, or **written permission**.
No active exploitation included — only passive & semi-passive recon.

---

# 📁 Tools in This Repository

| Tool Name                          | File                     | Description                                                                        |
| ---------------------------------- | ------------------------ | ---------------------------------------------------------------------------------- |
| **ReconNexus JS Secret Scanner**   | `js_secret_finder.py`    | Scans JavaScript files for secrets, tokens, API keys, OAuth tokens, etc.           |
| **ReconNexus HTTP Header Scanner** | `http_header_scanner.py` | Fast async scanner to detect server headers, tech stack, missing security headers. |
| **ReconNexus Wayback Miner**       | `wayback_miner.py`       | Advanced Wayback Machine CDX miner with filtering for sensitive files.             |

---

# 🔧 Installation (Kali Linux Friendly)

```bash
sudo apt update -y
sudo apt install -y git python3 python3-pip python3-venv

git clone https://github.com/PradyumnTiwareNexus/tools-js_secret_finder.py.git
cd tools-js_secret_finder.py

python3 -m venv venv
source venv/bin/activate
pip install aiohttp requests jsbeautifier lxml
```

(Optional) Add `.gitignore` to avoid committing results:

```bash
venv/
*.json
*.html
downloads/
```

---
# 🟣 Installation Demo


<p align="center">
  <img src="./DEMO Installation .png" width="55%" />
</p>

# 🟣 ReconNexus JS Secret Scanner

**File:** `js_secret_finder.py`

A modern, async, high-performance JS secret hunter.

### Run (Basic)

```bash
python3 js_secret_finder.py https://example.com
```

### Save results as JSON

```bash
python3 js_secret_finder.py https://example.com --format json -o results.json
```

### HTML Report

```bash
python3 js_secret_finder.py https://example.com --format html -o report.html
```

### Aggressive mode (entropy checks)

```bash
python3 js_secret_finder.py https://example.com --aggressive -o secrets.json
```

### Useful filters

```bash
# ignore analytics
--ignore google-analytics;googletag

# include only important CDN JS files
--only cdn;app;main
```

---

# 🟡 ReconNexus HTTP Header Scanner

**File:** `http_header_scanner.py`

Lightweight async header fingerprint tool.

### Basic usage

```bash
python3 http_header_scanner.py https://example.com
```

### Scan multiple URLs from file

```bash
while read url; do python3 http_header_scanner.py "$url"; done < urls.txt
```

### Detect missing security headers

* X-Frame-Options
* X-XSS-Protection
* Strict-Transport-Security
* Content-Security-Policy
* Server + X-Powered-By enumeration

---

# 🔵 ReconNexus Wayback Miner

**File:** `wayback_miner.py`

A powerful Wayback Machine CDX miner with advanced filtering.

### Basic pull

```bash
python3 wayback_miner.py -d example.com -o wayback.txt
```

### Filter sensitive extensions

```bash
python3 wayback_miner.py -d example.com --include-ext "sql,env,zip,db" -o filtered.txt
```

### Keyword filtering

```bash
python3 wayback_miner.py -d example.com --keyword "password,secret" -o secrets.txt
```

### Regex filtering

```bash
python3 wayback_miner.py -d example.com --regex "password|apikey|token" -o match.txt
```

### CDX-level filtering

```bash
--filter "~original:.*\.sql"
--filter-not "!mimetype:text/html"
```

(Optional) Download small files — **Use with permission**:

```bash
python3 wayback_miner.py -d example.com --download --max-download-size 200000
```

---

# 🔗 Recommended Recon Flow

```
1. Use Wayback Miner → collect endpoints
2. Filter URLs (.env, .sql, .zip, .db, passwords, backup)
3. Run JS Scanner → detect secrets/tokens
4. Run Header Scanner → fingerprint server
5. Analyze; exploit only with permission
```

---

# ❤️ Credits & Author

Made with dedication by **Pradyumn Tiware Nexus**
For ethical hacking, bug bounty & recon automation.

---
