#!/usr/bin/env python3
"""
HTTP Header Scanner - HEAD requests and basic fingerprinting.
Use responsibly and respect rate limits.
"""
import asyncio
import aiohttp
import sys

async def probe_url(session, url):
    try:
        async with session.head(url, timeout=10, allow_redirects=True) as r:
            return url, r.status, dict(r.headers)
    except Exception as e:
        return url, None, {"error": str(e)}

async def main(urls, concurrency=8):
    sem = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(headers={"User-Agent":"AllInOneRecon/1.0"}) as s:
        async def work(u):
            async with sem:
                return await probe_url(s, u)
        tasks = [work(u) for u in urls]
        for res in await asyncio.gather(*tasks):
            url, status, headers = res
            print(f"{url} -> {status}")
            for k in ("Server","X-Powered-By","Content-Security-Policy"):
                if k in headers:
                    print(f"  {k}: {headers[k]}")
            if "error" in headers:
                print("  error:", headers["error"])

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 tools/http_header_scanner.py https://example.com https://api.example.com")
        sys.exit(1)
    urls = sys.argv[1:]
    asyncio.run(main(urls))
