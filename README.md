# 🔍 OSINT Tools Suite

### JavaScript Secret Finder • HTTP Header Scanner • Wayback URL Miner

*By Pradyumn Tiware Nexus*

<p align="center">
  <img src="PradyumnTiwareNexus.png" width="100%" />
</p>

<p align="center">
  <a href="#"><img src="https://img.shields.io/badge/Made%20for-OSINT%20%26%20Bug%20Bounty-blue?style=for-the-badge"></a>
  <a href="#"><img src="https://img.shields.io/badge/Language-Python-yellow?style=for-the-badge"></a>
  <a href="#"><img src="https://img.shields.io/badge/Status-Active-brightgreen?style=for-the-badge"></a>
</p>

---

# 🚀 Overview

This repository contains **three powerful mini-OSINT tools**, specially crafted for:

* Bug Bounty Hunters
* Cybersecurity Researchers
* Penetration Testers
* Recon Engineers

These tools help you extract secrets, analyze HTTP headers, and mine archived URLs — all in a lightweight and fast way.

> ⚠ Use these tools **only on domains you own or have written permission to test**.

---

# 📦 Tools Included

## 1️⃣ **JS Secret Finder**

Extracts JavaScript files from webpages and finds sensitive information using regex signatures.

### 🔥 Detects:

* API Keys
* Tokens
* Authorization secrets
* AWS Keys
* Client IDs
* Hardcoded credentials

### ▶ Usage

```bash
python3 js_secret_finder.py https://example.com
```

### ▶ Multiple Sites

```bash
python3 js_secret_finder.py https://example.com https://api.example.com
```

---

## 2️⃣ **HTTP Header Scanner**

Asynchronous HTTP header scanner that performs fast fingerprinting.

### 🔥 Finds:

* Server header
* X-Powered-By
* Content-Security-Policy
* Missing security headers
* Framework signatures

### ▶ Usage

```bash
python3 http_header_scanner.py https://example.com https://admin.example.com
```

---

## 3️⃣ **Wayback URL Miner**

Fetches URLs from the **Wayback Machine archive (CDX API)**.

### 🔥 Useful for:

* Hidden endpoints
* Old admin panels
* Deleted files
* Historical URLs
* JS, PHP, backup files

### ▶ Usage

```bash
python3 wayback_miner.py example.com
```

---

# 🛠 Installation (Kali Linux)

### 1. Clone repo

```bash
git clone https://github.com/PradyumnTiwareNexus/tools-js_secret_finder.py
cd tools-js_secret_finder.py
```

### 2. Create virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install aiohttp requests
```

---

# 📂 Project Structure

```
tools-js_secret_finder.py/
│── LICENSE
│── README.md
│── js_secret_finder.py
│── http_header_scanner.py
│── wayback_miner.py
│── venv/ (optional)
```

---

# 📌 Recommended Use in Bug Bounty Workflows

### ✔ JS Secret Finder → Check for leaked secrets

### ✔ HTTP Header Scanner → Fingerprint tech & weaknesses

### ✔ Wayback Miner → Find hidden admin/endpoints

Recommended pairing:

* Subfinder
* httpx
* Nuclei
* Waymore
* Paramspider

---

# ⚠ Legal Disclaimer

These tools are provided for **ethical security research only**.
Using them on unauthorized domains may be illegal.

---

# 👑 Author

**Pradyumn Tiware Nexus**
Bug Bounty Hunter • Cybersecurity Researcher • Tool Developer
⭐ Follow for more tools:
[https://github.com/PradyumnTiwareNexus](https://github.com/PradyumnTiwareNexus)

---

# ⭐ Support

If you find this project useful, please give it a **⭐ STAR** on GitHub.
