#!/usr/bin/env python3
"""
ReconNexus Wayback Miner - advanced CDX query + filtering

Usage examples:
  # basic (text output)
  python3 reconnexus_wayback_miner.py -d example.com -o wayback.txt

  # text output, only non-html assets, collapse urlkey, include specific extensions
  python3 reconnexus_wayback_miner.py -d example.com --match domain --collapse urlkey \
    --filter-not-mimetype text/html --include-ext "zip,sql,env,db,sql.gz" -o filtered.txt

  # JSON output + regex keyword filter
  python3 reconnexus_wayback_miner.py -d example.com --format json --keyword "password|secret" -o out.json

  # produce output and optionally download small files (dangerous - use with permission)
  python3 reconnexus_wayback_miner.py -d example.com --include-ext "env,sql,zip" --download --max-download-size 524288 -o to-download.txt

Notes:
 - This script queries web.archive.org CDX API. It performs passive requests only.
 - Do not enable --download unless you understand what you're fetching.
"""
from __future__ import annotations
import argparse
import requests
import time
import re
import sys
import json
from typing import List, Iterable
from urllib.parse import urljoin, urlencode

USER_AGENT = "ReconNexus-Wayback/1.0 (+https://github.com/PradyumnTiwareNexus/)"
CDX_BASE = "https://web.archive.org/cdx/search/cdx"

# default sensitive extensions and keywords (you can override on CLI)
DEFAULT_SENSITIVE_EXTS = [
    "xls", "xlsx", "xml", "json", "pdf", "sql", "sql.gz", "sql.zip", "doc", "docx", "ppt", "pptx",
    "txt", "zip", "tar.gz", "tgz", "tar", "gz", "bz2", "7z", "rar", "log", "cache", "secret", "db",
    "sqlite", "backup", "bak", "yml", "yaml", "config", "cfg", "ini", "cnf", "env", "env.local",
    "properties", "csv", "md", "exe", "dll", "bin", "sh", "bat", "apk", "msi", "dmg", "crt", "pem",
    "key", "pub", "p12", "pfx", "sql.gz", "sql.zip"
]

DEFAULT_SENSITIVE_KEYWORDS = [
    "password", "passwd", "pwd", "secret", "token", "apikey", "api_key", "auth", "credential",
    "private", "key", "access_key", "aws", "git", "github", "database", "backup", "invoice", "passwords"
]

# helper: make safe comma/semicolon separated lists
def split_list(s: str) -> List[str]:
    if not s:
        return []
    s = s.replace(";", ",")
    parts = [p.strip().lower() for p in s.split(",") if p.strip()]
    return parts

def build_cdx_params(domain: str,
                     match_type: str = "domain",
                     collapse: str = None,
                     fl: str = "original",
                     output: str = "text",
                     limit: int = 100000,
                     filters: List[str] = None,
                     filter_not: List[str] = None,
                     statuscode: str = None,
                     mimetype: str = None) -> dict:
    """
    Build params to pass to CDX API. filter entries should be like:
      'filter=~original:.*\\.sql'
      'filter=!mimetype:text/html'
    We will pass multiple 'filter' params by repeating the key in requests.
    """
    params = {
        "url": f"*.{domain}/*" if match_type in ("domain", "host") else f"{domain}/*",
        "matchType": match_type,
        "output": output,
        "fl": fl,
        "limit": str(limit)
    }
    if collapse:
        params["collapse"] = collapse
    if statuscode:
        params["filter"] = f"statuscode:{statuscode}"
    # Note: requests doesn't support repeated params through dict easily for 'filter'
    return params

def cdx_request(params: dict, filters: List[str] = None, filter_not: List[str] = None, session: requests.Session = None, timeout: int = 30) -> requests.Response:
    """
    Send GET to CDX with optional repeated filter params.
    We'll construct the querystring manually to allow repeated filter entries.
    """
    base = CDX_BASE
    q = []
    for k, v in params.items():
        q.append((k, v))
    # add filter entries
    if filters:
        for f in filters:
            q.append(("filter", f))
    if filter_not:
        for f in filter_not:
            q.append(("filter", f))  # caller must prefix '!' for negation if needed
    # create raw querystring
    qs = urlencode(q, doseq=True)
    url = f"{base}?{qs}"
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}
    resp = sess.get(url, headers=headers, timeout=timeout)
    return resp

def parse_text_output(text: str) -> List[str]:
    """
    CDX 'text' output returns one URL per line (already 'original').
    We'll split, dedupe, and return.
    """
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    # dedupe preserving order
    seen = set()
    out = []
    for l in lines:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out

def parse_json_output(j: list) -> List[str]:
    """
    If output=json and fl=original, CDX returns list of lists -> first row might be header.
    We'll attempt to extract all 'original' entries.
    """
    out = []
    try:
        # If first row is header, skip
        for row in j:
            if isinstance(row, list):
                if len(row) >= 1:
                    out.append(row[0])
            elif isinstance(row, dict) and 'original' in row:
                out.append(row['original'])
            else:
                # fallback: string
                out.append(str(row))
    except Exception:
        pass
    # dedupe
    seen = set()
    o2 = []
    for v in out:
        if v not in seen:
            seen.add(v)
            o2.append(v)
    return o2

def filter_by_ext(urls: Iterable[str], include_ext: List[str], exclude_ext: List[str]) -> List[str]:
    inc = [e.lstrip(".").lower() for e in include_ext]
    exc = [e.lstrip(".").lower() for e in exclude_ext]
    out = []
    for u in urls:
        path = u.split("?")[0].split("#")[0].lower()
        ext = ""
        if "." in path:
            ext = path.rsplit(".", 1)[-1]
        if inc and ext not in inc:
            continue
        if exc and ext in exc:
            continue
        out.append(u)
    return out

def filter_by_keyword(urls: Iterable[str], keywords: List[str]) -> List[str]:
    if not keywords:
        return list(urls)
    kws = [k.lower() for k in keywords]
    out = []
    for u in urls:
        low = u.lower()
        if any(k in low for k in kws):
            out.append(u)
    return out

def filter_by_regex(urls: Iterable[str], regex_list: List[str]) -> List[str]:
    if not regex_list:
        return list(urls)
    patterns = [re.compile(r, re.I) for r in regex_list]
    out = []
    for u in urls:
        if any(p.search(u) for p in patterns):
            out.append(u)
    return out

def maybe_download(urls: Iterable[str], max_size: int = 262144, outdir: str = "downloads", session: requests.Session = None):
    """
    OPTIONAL: download files up to max_size bytes (default 256 KB).
    Downloads are risky — default not used. Caller must opt-in.
    """
    import os
    sess = session or requests.Session()
    headers = {"User-Agent": USER_AGENT}
    os.makedirs(outdir, exist_ok=True)
    results = []
    for u in urls:
        try:
            r = sess.head(u, headers=headers, allow_redirects=True, timeout=15)
            length = r.headers.get("Content-Length")
            if length and int(length) > max_size:
                print(f"[skip] {u} size {length} > max {max_size}")
                continue
            # fetch GET
            r2 = sess.get(u, headers=headers, stream=True, timeout=30)
            fname = os.path.join(outdir, os.path.basename(u.split("?")[0]) or f"file_{int(time.time())}")
            with open(fname, "wb") as fh:
                for chunk in r2.iter_content(8192):
                    fh.write(chunk)
            results.append((u, fname))
            print(f"[downloaded] {u} -> {fname}")
        except Exception as e:
            print(f"[error] {u} : {e}")
    return results

def human_print_list(title: str, items: List[str], limit: int = None):
    print(f"\n== {title} ({len(items)}) ==")
    if limit:
        items = items[:limit]
    for it in items:
        print(it)

def main():
    ap = argparse.ArgumentParser(prog="reconnexus_wayback_miner", description="ReconNexus Wayback Miner - advanced CDX filtering")
    ap.add_argument("-d", "--domain", required=True, help="Target domain (example.com) or host pattern")
    ap.add_argument("--match", choices=["domain","prefix","host"], default="domain", help="CDX matchType")
    ap.add_argument("--collapse", default="urlkey", help="collapse param (eg urlkey, digest)")
    ap.add_argument("--format", choices=["text","json"], default="text", help="CDX output format to request")
    ap.add_argument("--fl", default="original", help="CDX fl param (fields). default=original")
    ap.add_argument("--limit", type=int, default=100000, help="CDX limit (number of results). use responsibly")
    ap.add_argument("--filter", action="append", help="Add custom CDX filter (use repeated). e.g. 'mime:application/pdf' or '~original:.*\\.sql'")
    ap.add_argument("--filter-not", action="append", help="Add negated filters (prefix with '!') - will be sent as-is")
    ap.add_argument("--include-ext", help="Comma/semicolon separated extensions to include (eg: sql,zip,env)")
    ap.add_argument("--exclude-ext", help="Comma/semicolon separated extensions to exclude")
    ap.add_argument("--keyword", help="Comma separated keywords to filter results (case-insensitive)")
    ap.add_argument("--regex", help="Comma separated regex patterns to filter results")
    ap.add_argument("--output", "-o", default=None, help="Write final list to file (one per line)")
    ap.add_argument("--download", action="store_true", help="OPTIONAL: download listed files (use with caution)")
    ap.add_argument("--max-download-size", type=int, default=262144, help="Max bytes to download per file when --download (default 256KB)")
    ap.add_argument("--dedupe", action="store_true", default=True, help="Deduplicate results (default true)")
    ap.add_argument("--sensitive-exts", help="Comma list of sensitive extension candidates (overrides default)")
    ap.add_argument("--sensitive-keywords", help="Comma list of sensitive keywords (overrides default)")
    args = ap.parse_args()

    domain = args.domain.strip()
    match = args.match
    collapse = args.collapse
    fmt = args.format
    fl = args.fl
    limit = args.limit

    # prepare filters
    filters = []
    filter_not = []
    if args.filter:
        for f in args.filter:
            filters.append(f)
    if args.filter_not:
        for f in args.filter_not:
            filter_not.append(f)

    include_ext = split_list(args.include_ext)
    exclude_ext = split_list(args.exclude_ext)
    keywords = split_list(args.keyword)
    regex_list = [r.strip() for r in (args.regex or "").split(",") if r.strip()]

    sensitive_exts = split_list(args.sensitive_exts) if args.sensitive_exts else DEFAULT_SENSITIVE_EXTS
    sensitive_keywords = split_list(args.sensitive_keywords) if args.sensitive_keywords else DEFAULT_SENSITIVE_KEYWORDS

    # Build base params
    params = build_cdx_params(domain=domain, match_type=match, collapse=collapse, fl=fl, output=fmt, limit=limit)

    session = requests.Session()
    try:
        print(f"[+] Querying Wayback CDX for: {domain} (match={match}, collapse={collapse}, fl={fl}, output={fmt})")
        resp = cdx_request(params, filters=filters, filter_not=filter_not, session=session)
        if resp.status_code != 200:
            print(f"[!] CDX returned status {resp.status_code}")
            print(resp.text[:500])
            sys.exit(1)
        # parse results
        if fmt == "text":
            urls = parse_text_output(resp.text)
        else:
            try:
                j = resp.json()
                urls = parse_json_output(j)
            except Exception:
                urls = parse_text_output(resp.text)
        print(f"[+] Raw results: {len(urls)} entries")
        # apply extension filters first (if provided)
        if include_ext or exclude_ext:
            urls = filter_by_ext(urls, include_ext=include_ext, exclude_ext=exclude_ext)
            print(f"[+] After ext filters: {len(urls)} entries")
        # apply keyword filter
        if keywords:
            urls = filter_by_keyword(urls, keywords)
            print(f"[+] After keyword filters: {len(urls)} entries")
        # apply regex filters
        if regex_list:
            urls = filter_by_regex(urls, regex_list)
            print(f"[+] After regex filters: {len(urls)} entries")

        # If no explicit filters applied, produce a 'sensitive candidates' list by ext+keyword intersection
        sensitive_candidates = []
        if not (include_ext or keywords or regex_list):
            # build heuristics
            for u in urls:
                low = u.lower()
                ext_ok = any(low.endswith("." + e) for e in sensitive_exts)
                kw_ok = any(k in low for k in sensitive_keywords)
                if ext_ok or kw_ok:
                    sensitive_candidates.append(u)
            print(f"[+] Sensitive-looking candidates: {len(sensitive_candidates)}")

        # dedupe & sort
        final = urls
        if args.dedupe:
            seen = set()
            out = []
            for u in final:
                if u not in seen:
                    seen.add(u)
                    out.append(u)
            final = out
        final_sorted = sorted(final)

        # output to file or stdout
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                for u in final_sorted:
                    f.write(u + "\n")
            print(f"[+] Final list written to: {args.output} ({len(final_sorted)} entries)")
        else:
            human_print_list("Final results", final_sorted, limit=2000)

        # if no explicit filters and we found sensitive candidates, print them separately
        if sensitive_candidates:
            human_print_list("Sensitive candidates (heuristic)", sorted(set(sensitive_candidates)))

        # optional download
        if args.download and final_sorted:
            print("[!] Download enabled. Be careful. Starting downloads (size limit: {} bytes)".format(args.max_download_size))
            maybe_download(final_sorted, max_size=args.max_download_size, session=session)
    finally:
        session.close()

if __name__ == "__main__":
    main()
