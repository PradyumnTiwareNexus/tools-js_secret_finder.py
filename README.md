# 🔍 Tools Suite Secret Finder

### JavaScript Secret Finder • HTTP Header Scanner • Wayback URL Miner

*By Pradyumn Tiware Nexus*

<p align="center">
  <img src="PradyumnTiwareNexus.png" width="50%" />
</p>


> **Quick:** This README explains how to install and run the three ReconNexus tools in this repo:
>
> * `reconnexus_wayback_miner.py` (Wayback CDX miner)
> * `reconnexus_js_scanner.py` (async JS secret scanner)
> * `http_header_scanner.py` (async header probe)

---

## ⚠️ IMPORTANT — Legal & Safety

These tools are intended for **ethical security research** and **bug bounty** use only. Run them **only** against targets you own or have explicit, written permission to test. Do not enable active download options or aggressive heuristics against third-party targets without permission.

---

## 🔧 Kali Linux — Installation (copy & paste)

Open terminal and run these commands (assumes sudo access):

```bash
# 1) Update system
sudo apt update && sudo apt upgrade -y

# 2) Install Python venv and build deps
sudo apt install -y git python3-venv python3-pip build-essential python3-dev libssl-dev libffi-dev

# 3) Clone this repo (example)
git clone https://github.com/PradyumnTiwareNexus/<REPO_NAME>.git
cd <REPO_NAME>

# 4) Create & activate venv
python3 -m venv venv
source venv/bin/activate

# 5) Install runtime deps
pip install --upgrade pip
pip install aiohttp requests jsbeautifier lxml

# 6) Optional: create .gitignore to avoid committing keys/results
cat > .gitignore <<'EOF'
venv/
*.json
report*.html
downloads/
*.log
.env
EOF
```

Replace `<REPO_NAME>` with your repository name (for example `reconnexus-tools`).

---

## 📁 Files in this repo

* `reconnexus_wayback_miner.py` — passive Wayback CDX miner (text/json output, filters, optional download)
* `reconnexus_js_scanner.py` — merged async JS scanner (ReconNexus merged & upgraded script)
* `http_header_scanner.py` — async header fingerprinting tool
* `README.md` — this file
* `LICENSE` — MIT license

---

# 🔎 How to use each tool

Each section below shows short usage examples and recommended flags.

---

## 1) reconnexus_wayback_miner.py — Wayback CDX miner (passive)

**Purpose:** Harvest archived URLs from Wayback Machine with advanced filtering and heuristics.

### Basic usage (text output)

```bash
python3 reconnexus_wayback_miner.py -d example.com -o wayback.txt
```

### JSON output

```bash
python3 reconnexus_wayback_miner.py -d example.com --format json -o wayback.json
```

### Filter to likely sensitive extensions (heuristic)

```bash
python3 reconnexus_wayback_miner.py -d example.com --include-ext "env,sql,zip,pem,key" -o sensitive.txt
```

### Use keyword or regex filters (case-insensitive)

```bash
python3 reconnexus_wayback_miner.py -d example.com --keyword "password,secret" -o suspect.txt
python3 reconnexus_wayback_miner.py -d example.com --regex "password|secret|credentials" -o suspect.txt
```

### Optional: download small files (DANGEROUS — default off)

```bash
python3 reconnexus_wayback_miner.py -d example.com --include-ext "env,sql" --download --max-download-size 262144 -o to_download.txt
```

**Notes & tips:**

* `--collapse urlkey` deduplicates similar URLs (recommended).
* `--filter` and `--filter-not` allow raw CDX filters if you need specific control.
* Start passive (no download), inspect results, then optionally enable `--download` for very small files only.
* Output files can be fed into `uro` / `grep` pipelines for further filtering.

---

## 2) reconnexus_js_scanner.py — Async JS Secret Scanner (ReconNexus)

**Purpose:** Discover JS files on pages, download them concurrently, and scan for secrets via a large regex DB + optional entropy heuristics.

### Quick run (JSON output)

```bash
python3 reconnexus_js_scanner.py https://example.com -o results.json --format json
```

### HTML report (readable, styled)

```bash
python3 reconnexus_js_scanner.py https://example.com --format html -o report.html
```

### Aggressive mode (entropy + long-token heuristics)

**Only with permission** — this finds high-entropy tokens but has more false positives.

```bash
python3 reconnexus_js_scanner.py https://example.com --format html -o aggressive_report.html --aggressive
```

### Multiple targets & filters

```bash
python3 reconnexus_js_scanner.py https://one.example https://two.example -o merge.json
# Only include JS urls containing 'cdn' or 'app'
python3 reconnexus_js_scanner.py https://example.com --only cdn;app -o results.json
# Ignore analytics or common vendor files
python3 reconnexus_js_scanner.py https://example.com --ignore google-analytics;googletagmanager -o results.json
```

**Options you should know:**

* `--concurrency` (default 20) — increase for speed, but don't DoS targets.
* `--timeout` — request timeout seconds.
* `--cookie` / `--headers` — pass session cookies or headers to fetch authenticated JS.
* `--aggressive` — enable entropy-based heuristics (opt-in).

**Outputs:**

* JSON: `{meta, findings}` with each JS URL and found matches.
* HTML: stylized report showing matches, context and entropy scores (if aggressive).

---

## 3) http_header_scanner.py — Async Header Fingerprinter

**Purpose:** Quickly probe a list of URLs (HEAD/GET) and extract key headers like `Server`, `X-Powered-By`, `CSP`.

### Usage

```bash
python3 http_header_scanner.py https://example.com https://admin.example.com
```

### Run from file of URLs

```bash
cat urls.txt | xargs -n1 -P8 python3 http_header_scanner.py
# Or run the script in a loop (preferred):
while read u; do python3 http_header_scanner.py "$u"; done < urls.txt
```

**Options:**

* Adjust concurrency inside the script if needed. It uses `aiohttp` and a default concurrency (changeable in code).
* Useful for spotting outdated servers, missing security headers, and tech fingerprinting.

---

# 🔄 Example Recon Flow (recommended)

1. Run Wayback Miner to harvest potential historical endpoints:

```bash
python3 reconnexus_wayback_miner.py -d example.com -o wayback.txt
```

2. Filter `wayback.txt` for interesting extensions or keywords (e.g., `.env`, `password`, `backup`) and produce a smaller candidate list.
3. Use `reconnexus_js_scanner.py` against targets or saved HTML/JS: scan live pages for secrets.
4. Probe live endpoints with `http_header_scanner.py` to fingerprint servers and check security headers.
5. Triage findings manually and verify with permissioned active testing (e.g., POST, login attempts only if allowed).

---

# 🧰 Recommended file & repo hygiene

* Add these to `.gitignore`:

```
venv/
report*.html
*.json
downloads/
.env
```

* **Never** commit API keys, cookies, or downloaded secret files to public repos.
* Use `direnv` or environment variables to store API keys for other modules.

---

# ⚙ Troubleshooting

* `ModuleNotFoundError` → ensure venv is activated: `source venv/bin/activate` then `pip install -r requirements`.
* `requests` errors (Wayback) → network or Wayback rate-limit; retry after delay.
* Unexpected large outputs → use `--include-ext` or `--keyword` to narrow results.

---

# 📝 Add this README to your repo

Copy this entire file content and paste it as `README.md` in your tool repo root. After that run:

```bash
git add README.md
git commit -m "Add user-friendly README for ReconNexus tools"
git push origin main
```

---

## ✅ Need help pushing changes?

Tell me: **I want you to give me git commands** and I will provide exact commands to add & push this file with examples. Or paste here the error you get when editing and I will fix it for you.

---

Made by **ReconNexus** — stay responsible, stay ethical.
