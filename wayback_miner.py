#!/usr/bin/env python3
"""
Wayback URL Miner (passive)
Uses the Wayback CDX API to get archived URLs for a domain.
No active scanning. Safe to run.
"""
import requests
import sys
from urllib.parse import quote_plus

CDX_API = "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=json&fl=original&collapse=urlkey&limit=1000"

def fetch_wayback(domain):
    url = CDX_API.format(domain=quote_plus(domain))
    r = requests.get(url, timeout=15, headers={"User-Agent":"AllInOneRecon/1.0"})
    if r.status_code != 200:
        print("Wayback API error:", r.status_code)
        return []
    try:
        data = r.json()
    except Exception:
        # fallback: parse lines
        lines = r.text.splitlines()
        return lines
    # first entry is header if json
    urls = [row[0] for row in data[1:]] if len(data) > 1 else []
    return urls

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 tools/wayback_miner.py example.com")
        sys.exit(1)
    domain = sys.argv[1]
    urls = fetch_wayback(domain)
    for u in urls:
        print(u)
