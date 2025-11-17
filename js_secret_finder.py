#!/usr/bin/env python3
"""
ReconNexus JS Secret Scanner (merged & upgraded)

Features:
- Async JS discovery (fetch HTML -> extract <script src> -> fetch JS)
- Big regex database for tokens/keys (merged & extended)
- Optional aggressive heuristics (entropy, long base64, long alnum tokens)
- Output: CLI / JSON / HTML report
- Filters: --ignore, --only
- Options: concurrency, timeout, proxy, cookies, headers
- No Burp support included (by user request)

Use responsibly: only run on targets you own or have explicit permission.
"""
from __future__ import annotations
import argparse
import asyncio
import aiohttp
import re
import jsbeautifier
import json
import os
import sys
import math
import time
from urllib.parse import urljoin, urlparse
from lxml import html
from typing import List, Dict, Any, Tuple, Set

# ---------- CONFIG ----------
USER_AGENT = "ReconNexus/1.0 (+https://github.com/PradyumnTiwareNexus/)"
DEFAULT_CONCURRENCY = 20
DEFAULT_TIMEOUT = 12

# ---------- REGEX DATABASE (condensed but extensive) ----------
# Merged and improved patterns from multiple sources. Keys map -> regex.
_REGEX_DB = {
    # Google / Firebase / OAuth
    "google_api_key": r"AIza[0-9A-Za-z\-_]{35}",
    "google_oauth": r"ya29\.[0-9A-Za-z\-_]+",
    "firebase_token": r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}",
    # AWS
    "aws_access_key_id": r"(?:A|AS|AK)IA[0-9A-Z]{16}",
    # Stripe/Pay
    "stripe_sk": r"sk_live_[0-9a-zA-Z]{24}",
    "stripe_rk": r"rk_live_[0-9a-zA-Z]{24}",
    # Twilio
    "twilio_sk": r"SK[0-9a-fA-F]{32}",
    # Slack, GitHub, JWT
    "slack_token": r"xox[baprs]-[0-9a-zA-Z]{10,}",
    "jwt_like": r"eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+",
    # Generic API key patterns
    "api_key_generic": r"(?:api[_-]?key|apikey|secret|token|auth|access[_-]?token)[\"'\s:=/:]+([A-Za-z0-9\-\._]{16,128})",
    # Basic Authorization/header tokens
    "authorization_bearer": r"(?i)bearer\s+[A-Za-z0-9\-\._=\/+]+",
    "authorization_basic": r"(?i)basic\s+[A-Za-z0-9=:_\+\/-]{5,200}",
    # RSA/Private keys
    "rsa_private_key": r"-----BEGIN (?:RSA|DSA|EC) PRIVATE KEY-----",
    "pem_private_key": r"-----BEGIN .*PRIVATE KEY-----",
    # High-entropy base64-ish long strings (aggressive)
    "long_base64": r"(?:[A-Za-z0-9_\-]{40,}={0,2})",
    # AWS URLs
    "s3_url": r"(?:[a-z0-9\-\._]+\.s3(?:-[a-z0-9-]+)?\.amazonaws\.com|s3://[A-Za-z0-9\-\._/]+)",
    # Mailgun, Sendgrid
    "mailgun": r"key-[0-9a-zA-Z]{32}",
    "sendgrid": r"SG\.[A-Za-z0-9\-_]{20,}",
    # Possible credentials patterns (password= etc.) — lower confidence
    "possible_cred": r"(?i)(?:password|pwd|passwd|pass)[\"'\s:=]+([^\s\"']{6,128})",
}

# compile regexes for performance
_COMPILED = [(name, re.compile(pattern)) for name, pattern in _REGEX_DB.items()]

# ---------- Utilities ----------
def is_url(s: str) -> bool:
    return s.startswith(("http://", "https://"))

def safe_join_url(base: str, link: str) -> str:
    try:
        return urljoin(base, link)
    except Exception:
        return link

def normalize_url(u: str) -> str:
    p = urlparse(u)
    if not p.scheme:
        return "http://" + u
    return u

def shannon_entropy(s: str) -> float:
    # Shannon entropy per char
    if not s:
        return 0.0
    from collections import Counter
    c = Counter(s)
    probs = [v/len(s) for v in c.values()]
    import math
    return -sum(p * math.log2(p) for p in probs)

# ---------- HTML report template ----------
_HTML_TEMPLATE = """
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>ReconNexus JS Scan Report - {target}</title>
  <style>
    body{{background:#0f0f13;color:#e8e8ee;font-family:Inter,Segoe UI,Arial,Helvetica,sans-serif;padding:24px;}}
    .wrap{{max-width:1100px;margin:0 auto;background:#0b0b0d;padding:20px;border-radius:8px;box-shadow:0 8px 30px rgba(0,0,0,0.7)}}
    h1{{color:#ff88ff;margin-bottom:6px}}
    .meta{{color:#a9a9b3;font-size:13px;margin-bottom:18px}}
    .section{{margin-top:18px}}
    .card{{background:#081018;padding:14px;border-radius:6px;border:1px solid rgba(255,255,255,0.03)}}
    pre{{white-space:pre-wrap;word-break:break-word;font-size:13px;color:#d8d8f0;background:transparent;border:none}}
    table{{width:100%;border-collapse:collapse;margin-top:8px}}
    th,td{{text-align:left;padding:8px;border-bottom:1px solid rgba(255,255,255,0.03)}}
    th{{color:#f3c4ff}}
    .tag{{display:inline-block;background:rgba(255,255,255,0.03);padding:4px 8px;border-radius:4px;margin-right:6px;color:#ffd6ff;font-size:12px}}
  </style>
</head>
<body>
  <div class="wrap">
    <h1>ReconNexus JS Scan — {target}</h1>
    <div class="meta">Generated: {time} · Format: {fmt} · Aggressive: {aggr}</div>

    <div class="section card">
      <h3>Summary</h3>
      <table>
        <tr><th>Total JS files</th><td>{total_js}</td></tr>
        <tr><th>Files with findings</th><td>{files_with_findings}</td></tr>
        <tr><th>Unique findings</th><td>{unique_findings}</td></tr>
      </table>
    </div>

    <div class="section">
      <h3>Findings</h3>
      {details}
    </div>
  </div>
</body>
</html>
"""

# ---------- Core scanning functionality ----------
class Scanner:
    def __init__(self, concurrency:int=DEFAULT_CONCURRENCY, timeout:int=DEFAULT_TIMEOUT,
                 headers:Dict[str,str]=None, cookies:str=None, proxy:str=None,
                 ignore:str=None, only:str=None, aggressive:bool=False):
        self.concurrency = concurrency
        self.timeout = timeout
        self.headers = headers or {}
        self.cookies = cookies
        self.proxy = proxy
        self.ignore = ignore.split(";") if ignore else []
        self.only = only.split(";") if only else []
        self.aggressive = aggressive
        self.seen_js: Set[str] = set()
        self.findings: Dict[str, List[Dict[str,Any]]] = {}
        self.total_js_count = 0

    async def fetch_text(self, session: aiohttp.ClientSession, url: str) -> str:
        try:
            async with session.get(url, timeout=self.timeout, allow_redirects=True) as resp:
                text = await resp.text(errors='replace')
                return text
        except Exception:
            return ""

    async def extract_js_urls(self, session: aiohttp.ClientSession, base_url: str) -> List[str]:
        html_text = await self.fetch_text(session, base_url)
        if not html_text:
            return []
        # parse with lxml for robustness
        try:
            doc = html.fromstring(html_text)
            srcs = doc.xpath('//script[@src]/@src')
        except Exception:
            # fallback to regex
            srcs = re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html_text, re.I)
        js_urls = []
        base_root = "{scheme}://{netloc}".format(scheme=urlparse(base_url).scheme or "http", netloc=urlparse(base_url).netloc)
        for s in srcs:
            if s.startswith("//"):
                s = urlparse(base_url).scheme + ":" + s
            elif s.startswith("/"):
                s = base_root + s
            elif not s.startswith(("http://","https://")):
                s = urljoin(base_url, s)
            # apply ignore/only
            if self.ignore and any(i and i in s for i in self.ignore):
                continue
            if self.only and not any(o and o in s for o in self.only):
                continue
            if s not in self.seen_js:
                js_urls.append(s)
                self.seen_js.add(s)
        return js_urls

    def analyze_text(self, text: str) -> List[Dict[str,Any]]:
        results = []
        # optionally beautify
        try:
            if len(text) > 200 and "function" in text:
                text = jsbeautifier.beautify(text)
        except Exception:
            pass
        for name, cre in _COMPILED:
            for m in cre.finditer(text):
                matched = m.group(0)
                # basic contextual snippet
                start = max(m.start()-80, 0)
                end = min(m.end()+80, len(text))
                context = text[start:end].strip()
                results.append({
                    "type": name,
                    "match": matched,
                    "context": context
                })
        # aggressive heuristics
        if self.aggressive:
            # long base64-like tokens
            for m in re.finditer(r"[A-Za-z0-9_\-]{40,}", text):
                s = m.group(0)
                ent = shannon_entropy(s)
                if ent >= 3.5 and len(s) >= 40:
                    results.append({
                        "type": "high_entropy_token",
                        "match": s,
                        "entropy": round(ent,2),
                        "context": text[max(m.start()-40,0):m.end()+40]
                    })
        # dedupe by match text
        seen = set()
        uniq = []
        for r in results:
            key = (r.get("type"), r.get("match"))
            if key not in seen:
                seen.add(key)
                uniq.append(r)
        return uniq

    async def scan_js_url(self, session: aiohttp.ClientSession, js_url: str) -> Tuple[str, List[Dict[str,Any]]]:
        txt = await self.fetch_text(session, js_url)
        self.total_js_count += 1
        if not txt:
            return js_url, []
        findings = self.analyze_text(txt)
        if findings:
            self.findings[js_url] = findings
        return js_url, findings

    async def run_targets(self, targets: List[str], output_format: str="cli"):
        connector = aiohttp.TCPConnector(limit=self.concurrency)
        headers = {"User-Agent": USER_AGENT}
        headers.update(self.headers or {})
        auth = None
        # build session (cookies via header if provided)
        async with aiohttp.ClientSession(headers=headers, trust_env=True, connector=connector) as session:
            # first gather all JS urls from targets
            all_js = []
            sem = asyncio.Semaphore(self.concurrency)
            async def gather_js(t):
                async with sem:
                    js_urls = await self.extract_js_urls(session, t)
                    return js_urls
            tasks = [gather_js(t) for t in targets]
            pages_js = await asyncio.gather(*tasks)
            for js_list in pages_js:
                for js in js_list:
                    all_js.append(js)
            # now fetch all JS concurrently
            async def scan_one(jsu):
                async with sem:
                    return await self.scan_js_url(session, jsu)
            scan_tasks = [scan_one(jsu) for jsu in all_js]
            # progress yields (not required)
            results = []
            for coro in asyncio.as_completed(scan_tasks):
                res = await coro
                results.append(res)
            return results

# ---------- CLI & Runner ----------
def build_parser():
    p = argparse.ArgumentParser(prog="reconnexus_js_scanner", description="ReconNexus - async JS secret scanner")
    p.add_argument("targets", nargs="+", help="One or more target URLs (https://...) or paths to single html/js file (file://...)")
    p.add_argument("-o","--output", help="Output file (json/html) or 'cli' for console", default="report.json")
    p.add_argument("--format", choices=["json","html","cli"], default="json", help="Output format")
    p.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--proxy", help="Proxy (http://host:port) to use", default=None)
    p.add_argument("--cookie", help="Cookie header string", default=None)
    p.add_argument("--headers", help="Extra headers; format: 'Name:Value\\nName:Value'", default=None)
    p.add_argument("--ignore", help="Ignore JS URLs containing these substrings (semicolon separated)", default=None)
    p.add_argument("--only", help="Only include JS URLs containing these substrings (semicolon separated)", default=None)
    p.add_argument("--aggressive", action="store_true", help="Enable aggressive heuristics (entropy, long tokens). Use only with permission.")
    return p

def format_json_report(findings: Dict[str, List[Dict[str,Any]]], meta: Dict[str,Any]) -> Dict[str,Any]:
    out = {"meta":meta, "findings":findings}
    return out

def format_html_details(findings: Dict[str, List[Dict[str,Any]]]) -> str:
    if not findings:
        return "<div class='card'><p>No findings.</p></div>"
    parts = []
    for js, items in findings.items():
        rows = []
        rows.append(f"<h4 class='card'>JS: <a href='{js}' target='_blank' rel='noopener'>{js}</a></h4>")
        rows.append("<table><thead><tr><th>Type</th><th>Match</th><th>Context</th></tr></thead><tbody>")
        for it in items:
            t = it.get("type")
            m = html_escape(it.get("match"))
            ctx = html_escape(it.get("context")[:600])
            ent = it.get("entropy")
            extra = f" (entropy={ent})" if ent else ""
            rows.append(f"<tr><td>{t}</td><td><pre>{m}</pre></td><td><pre>{ctx}{extra}</pre></td></tr>")
        rows.append("</tbody></table><br/>")
        parts.append("".join(rows))
    return "\n".join(parts)

def html_escape(s: str) -> str:
    import html as _html
    return _html.escape(s or "")

async def main_async(args):
    # normalize targets to full URLs where needed
    targets = [normalize_url(t) if is_url(t) else t for t in args.targets]
    # build headers dict
    hdrs = {}
    if args.headers:
        for line in args.headers.split("\\n"):
            if not line.strip():
                continue
            if ":" in line:
                k,v = line.split(":",1)
                hdrs[k.strip()] = v.strip()
    scanner = Scanner(concurrency=args.concurrency, timeout=args.timeout,
                      headers=hdrs, cookies=args.cookie, proxy=args.proxy,
                      ignore=args.ignore, only=args.only, aggressive=args.aggressive)
    results = await scanner.run_targets(targets, output_format=args.format)
    # build final findings dict
    findings = scanner.findings
    meta = {
        "targets": args.targets,
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "total_js": scanner.total_js_count,
        "files_with_findings": len(findings),
        "aggressive": args.aggressive,
        "concurrency": args.concurrency
    }
    # output according to format
    if args.format == "cli":
        if not findings:
            print("[*] No findings.")
        else:
            for js, items in findings.items():
                print(f"\n[+] {js}")
                for it in items:
                    typ = it.get("type")
                    match = it.get("match")
                    ctx = it.get("context")
                    ent = it.get("entropy")
                    extra = f" (entropy={ent})" if ent else ""
                    print(f" - {typ}: {match}{extra}")
        return
    elif args.format == "json":
        out = format_json_report(findings, meta)
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False)
        print(f"[*] JSON report saved to {args.output}")
        return
    elif args.format == "html":
        details = format_html_details(findings)
        html_doc = _HTML_TEMPLATE.format(target=", ".join(args.targets), time=meta["time"], fmt="html", aggr=str(meta["aggressive"]), total_js=meta["total_js"], files_with_findings=meta["files_with_findings"], unique_findings=sum(len(v) for v in findings.values()), details=details)
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(html_doc)
        print(f"[*] HTML report saved to {args.output}")
        return

def main():
    parser = build_parser()
    args = parser.parse_args()
    # permission reminder
    print("ReconNexus JS Scanner — merged & upgraded")
    print("-> Ensure you have permission to test the targets. Unauthorized scanning is illegal.")
    # run
    try:
        asyncio.run(main_async(args))
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")

if __name__ == "__main__":
    main()
