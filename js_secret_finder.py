#!/usr/bin/env python3
"""
JS Secret Finder (passive-first)
- Fetches HTML of resolved hosts, extracts JS file URLs, fetches JS and scans for suspicious tokens (regex).
- USE WITH PERMISSION for active fetching. Passive-only if you feed it saved HTML.
"""
import re
import asyncio
import aiohttp
from urllib.parse import urljoin, urlparse
import sys

SUSPECT_PATTERNS = [
    r"api[_-]?key\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
    r"access[_-]?token\s*[:=]\s*[\"']([A-Za-z0-9_\-]{16,})[\"']",
    r"client[_-]?id\s*[:=]\s*[\"']([A-Za-z0-9_\-]{8,})[\"']",
    r"aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*[\"']([A-Z0-9]{16,})[\"']"
]

async def fetch_text(session, url):
    try:
        async with session.get(url, timeout=10) as r:
            return await r.text()
    except Exception:
        return ""

async def extract_js_from_url(session, base_url):
    html = await fetch_text(session, base_url)
    js_urls = set()
    # simple regex to find script src
    for m in re.findall(r'<script[^>]+src=["\\\']([^"\\\']+)["\\\']', html, re.I):
        js_urls.add(urljoin(base_url, m))
    return js_urls

async def scan_js(session, js_url):
    txt = await fetch_text(session, js_url)
    findings = []
    for pat in SUSPECT_PATTERNS:
        for m in re.findall(pat, txt):
            findings.append((pat, m))
    return findings

async def main(targets):
    print("[*] JS Secret Finder - passive-first. Ensure permission.")
    async with aiohttp.ClientSession(headers={"User-Agent":"AllInOneRecon/1.0"}) as s:
        for t in targets:
            print(f"[+] Scanning {t}")
            js_urls = await extract_js_from_url(s, t)
            for j in js_urls:
                f = await scan_js(s, j)
                if f:
                    print(f"  -> {j} : {f}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tools/js_secret_finder.py https://example.com")
        sys.exit(1)
    targets = sys.argv[1:]
    asyncio.run(main(targets))
